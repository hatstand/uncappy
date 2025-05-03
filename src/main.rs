use defer::defer;
use log::{debug, error, info};
use std::error::Error;
use windows::Win32::Foundation::{GetLastError, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP,
    VIRTUAL_KEY, VK_CAPITAL, VK_ESCAPE,
};
use windows::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, CreateWindowExW, DefWindowProcW, DestroyIcon, GetMessageW, LoadIconW,
    RegisterClassExW, SetWindowsHookExA, UnhookWindowsHookEx, UnregisterClassW, CS_DBLCLKS,
    HWND_MESSAGE, IDI_QUESTION, KBDLLHOOKSTRUCT, MSG, WH_KEYBOARD_LL, WINDOW_EX_STYLE,
    WINDOW_STYLE, WM_APP, WM_KEYUP, WM_SYSKEYUP, WNDCLASSEXW,
};
use windows_core::PCWSTR;

// const UNCAPPY_TASKBAR_CB_ID: usize = (WM_APP + 0x4243) as usize;
const UNCAPPY_TASKBAR_ICON_ID: u32 = 42;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    unsafe {
        let module = GetModuleHandleW(None)?;
        // Register a window class for the taskbar icon.
        let class_name = PCWSTR("Uncappy\0".encode_utf16().collect::<Vec<u16>>().as_ptr());
        let class = RegisterClassExW(&WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_DBLCLKS,
            lpfnWndProc: Some(window_callback),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: module.into(),
            lpszClassName: class_name,
            ..Default::default()
        });
        debug!("Class registered: {:?}", class);
        defer!({
            // Unregister the class when done.
            let _ = UnregisterClassW(class_name, Some(module.into()));
        });

        // Create a message-only window.
        // https://learn.microsoft.com/en-us/windows/win32/winmsg/window-features#message-only-windows
        let window = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class_name,
            PCWSTR(
                "Uncappy Window\0"
                    .encode_utf16()
                    .collect::<Vec<u16>>()
                    .as_ptr(),
            ),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(module.into()),
            None,
        )
        .inspect_err(|err| {
            error!("Failed to create window: {:?} {:?}", err, GetLastError());
        })?;
        debug!("Window created: {:?}", window);

        // ShowWindow(window, SW_SHOWDEFAULT).ok()?;
        // debug!("Window shown: {:?}", window);

        // Register a low-level keyboard hook that receives all keyboard events on the system.
        let hook_id = SetWindowsHookExA(WH_KEYBOARD_LL, Some(hook_callback), None, 0)?;
        defer!({
            let _ = UnhookWindowsHookEx(hook_id);
        });

        debug!("Setting up taskbar icon");
        // hinstance as None implies loading from the system.
        let icon = LoadIconW(None, IDI_QUESTION)?;
        debug!("Icon loaded: {:?}", icon);
        defer!({
            // Unload the icon when done.
            debug!("Destroying icon: {:?}", icon);
            let _ = DestroyIcon(icon);
        });
        debug!("Setting up taskbar icon");
        Shell_NotifyIconW(
            NIM_ADD,
            &mut NOTIFYICONDATAW {
                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: window,
                uID: UNCAPPY_TASKBAR_ICON_ID,
                hIcon: icon,
                szTip: [0; 128],
                uFlags: NIF_ICON | NIF_TIP,
                ..Default::default()
            },
        )
        .ok()?;
        defer!({
            // Remove the icon when done.
            debug!("Removing taskbar icon");
            let _ = Shell_NotifyIconW(
                NIM_DELETE,
                &mut NOTIFYICONDATAW {
                    cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                    hWnd: window,
                    uID: UNCAPPY_TASKBAR_ICON_ID,
                    ..Default::default()
                },
            );
        });

        info!("Running...");
        loop {
            let mut msg = MSG::default();
            GetMessageW(&mut msg, None, 0, 0).ok()?;
            debug!("Message received: {:?}", msg);
        }
    }
}

const UNCAPPY_INFO: usize = (WM_APP + 0x4242) as usize;

unsafe extern "system" fn window_callback(
    hwnd: windows::Win32::Foundation::HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // Handle messages sent to the taskbar icon.
    if msg == WM_APP {
        match wparam.0 as u32 {
            UNCAPPY_TASKBAR_ICON_ID => {
                // Handle taskbar icon messages here.
                debug!("Taskbar icon message received");
                return LRESULT(0);
            }
            _ => {
                // Ignore other messages.
                debug!("Unknown taskbar icon message: {:#x}", wparam.0 as u32);
            }
        }
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

// With reference to https://github.com/susam/uncap
unsafe extern "system" fn hook_callback(ncode: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if ncode < 0 {
        return CallNextHookEx(None, ncode, wparam, lparam);
    }
    let p: &KBDLLHOOKSTRUCT = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
    let key_code = VIRTUAL_KEY(p.vkCode as u16);
    match key_code {
        VK_CAPITAL => {
            if p.dwExtraInfo == UNCAPPY_INFO {
                // Skip our own events.
                return LRESULT(1);
            }
            // Synthesize a key event to remap the Caps Lock key to Escape.
            let dw_flags: KEYBD_EVENT_FLAGS =
                if wparam.0 as u32 == WM_KEYUP || wparam.0 as u32 == WM_SYSKEYUP {
                    KEYEVENTF_KEYUP
                } else {
                    KEYBD_EVENT_FLAGS(0)
                };
            let remapped = KEYBDINPUT {
                wVk: VK_ESCAPE,
                wScan: 0,
                dwFlags: dw_flags,
                time: 0,
                dwExtraInfo: UNCAPPY_INFO,
            };
            let inputs = [INPUT {
                r#type: INPUT_KEYBOARD,
                Anonymous: INPUT_0 { ki: remapped },
            }];
            match SendInput(&inputs, size_of::<INPUT>() as i32) {
                // Should return 1 (the number of events sent) on success.
                1 => {
                    debug!("Key remapped successfully");
                }
                0 => {
                    error!("Failed to remap key: {:?}", GetLastError());
                }
                n => {
                    error!("Failed to remap key: {:?}", n);
                }
            }
            LRESULT(1)
        }
        _ => {
            // Delegate to the next hook in the chain.
            debug!("Other key pressed: {:#x}", key_code.0 as i32);
            CallNextHookEx(None, ncode, wparam, lparam)
        }
    }
}
