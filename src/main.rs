use defer::defer;
use log::{debug, error, info};
use std::cell::LazyCell;
use std::error::Error;
use windows::Win32::Foundation::{GetLastError, HWND, LPARAM, LRESULT, POINT, RECT, SIZE, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP,
    VIRTUAL_KEY, VK_CAPITAL, VK_ESCAPE,
};
use windows::Win32::UI::Shell::{
    Shell_NotifyIconGetRect, Shell_NotifyIconW, NIF_GUID, NIF_ICON, NIF_MESSAGE, NIM_ADD,
    NIM_DELETE, NIM_SETVERSION, NOTIFYICONDATAW, NOTIFYICONDATAW_0, NOTIFYICONIDENTIFIER,
    NOTIFYICON_VERSION_4,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CalculatePopupWindowPosition, CallNextHookEx, CheckMenuItem, CreatePopupMenu, CreateWindowExW,
    DefWindowProcW, DestroyIcon, DispatchMessageW, DrawMenuBar, GetCursorPos, GetMenuItemInfoW,
    GetMessageW, GetWindowLongPtrW, HiliteMenuItem, InsertMenuItemW, LoadIconW, ModifyMenuW,
    MrmResourceIndexerMessageSeverity, RegisterClassExW, SetForegroundWindow, SetMenuItemInfoW,
    SetWindowLongPtrW, SetWindowsHookExA, TrackPopupMenuEx, UnhookWindowsHookEx, UnregisterClassW,
    GWLP_USERDATA, HMENU, IDI_QUESTION, KBDLLHOOKSTRUCT, MENUITEMINFOW, MENU_ITEM_STATE,
    MFS_CHECKED, MFS_ENABLED, MFS_HILITE, MFS_UNHILITE, MFT_STRING, MF_BYPOSITION, MF_HILITE,
    MF_UNHILITE, MIIM_CHECKMARKS, MIIM_FTYPE, MIIM_STATE, MIIM_STRING, MSG, TPM_BOTTOMALIGN,
    TPM_LEFTALIGN, TPM_RIGHTALIGN, TPM_RIGHTBUTTON, WH_KEYBOARD_LL, WINDOW_EX_STYLE, WINDOW_STYLE,
    WM_APP, WM_COMMAND, WM_KEYUP, WM_LBUTTONUP, WM_MENUSELECT, WM_NCACTIVATE, WM_RBUTTONUP,
    WM_SYSKEYUP, WNDCLASSEXW,
};
use windows_core::{GUID, PCWSTR, PWSTR};

const UNCAPPY_TASKBAR_CB_ID: u32 = WM_APP + 1;

pub fn LOWORD(l: isize) -> isize {
    l & 0xffff
}

pub fn HIWORD(l: isize) -> isize {
    (l >> 16) & 0xffff
}

pub fn GET_X_LPARAM(l: usize) -> i32 {
    (l & 0xffff) as i32
}

pub fn GET_Y_LPARAM(l: usize) -> i32 {
    ((l >> 16) & 0xffff) as i32
}

struct Uncappy {
    window: HWND,
    popup_menu: HMENU,
}

fn toggle_checked(current_state: MENU_ITEM_STATE) -> MENU_ITEM_STATE {
    if current_state & MFS_CHECKED == MFS_CHECKED {
        current_state & !MFS_CHECKED
    } else {
        current_state | MFS_CHECKED
    }
}

impl Uncappy {
    fn show_popup_menu(&self, x: i32, y: i32) -> Result<(), Box<dyn Error>> {
        debug!("Showing popup menu at ({}, {})", x, y);
        unsafe {
            // Required to ensure the popup menu disappears again when a user clicks elsewhere.
            SetForegroundWindow(self.window).ok()?;
            TrackPopupMenuEx(
                self.popup_menu,
                TPM_LEFTALIGN.0 | TPM_BOTTOMALIGN.0 | TPM_RIGHTBUTTON.0,
                x,
                y,
                self.window,
                None,
            )
            .ok()?;
        }
        Ok(())
    }

    fn menu_selection(&self, id: u32) -> Result<(), Box<dyn Error>> {
        debug!("Menu item selected: {}", id);
        unsafe {
            let mut mii = MENUITEMINFOW {
                cbSize: std::mem::size_of::<MENUITEMINFOW>() as u32,
                fMask: MIIM_STATE,
                ..Default::default()
            };
            GetMenuItemInfoW(self.popup_menu, id, true, &mut mii)?;
            debug!("Menu check state: {:?}", mii.fState & MFS_CHECKED);
            mii.fMask = MIIM_STATE;
            mii.fState = toggle_checked(mii.fState);
            SetMenuItemInfoW(self.popup_menu, id, true, &mut mii)?;
        }
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    unsafe {
        let module = GetModuleHandleW(None)?;
        // Register a window class for the taskbar icon.
        let class_name = PCWSTR("Uncappy\0".encode_utf16().collect::<Vec<u16>>().as_ptr());
        let class = RegisterClassExW(&WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(window_callback),
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
            PCWSTR(class as *const u16),
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
            None,
            None,
            Some(module.into()),
            None,
        )
        .inspect_err(|err| {
            error!("Failed to create window: {:?} {:?}", err, GetLastError());
        })?;
        debug!("Window created: {:?}", window);

        let uncappy = Uncappy {
            window,
            popup_menu: create_popup_menu()?,
        };
        SetWindowLongPtrW(window, GWLP_USERDATA, &uncappy as *const _ as isize);

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
        let guid = GUID::new()?;
        debug!("adding to taskbar");
        let notify_icon_data = &mut NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: window,
            hIcon: icon,
            guidItem: guid,
            uFlags: NIF_ICON | NIF_MESSAGE | NIF_GUID,
            uCallbackMessage: UNCAPPY_TASKBAR_CB_ID,
            Anonymous: NOTIFYICONDATAW_0 {
                uVersion: NOTIFYICON_VERSION_4,
            },
            ..Default::default()
        };
        Shell_NotifyIconW(NIM_ADD, notify_icon_data).ok()?;
        defer!({
            // Remove the icon when done.
            debug!("Removing taskbar icon");
            let _ = Shell_NotifyIconW(
                NIM_DELETE,
                &mut NOTIFYICONDATAW {
                    cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                    hWnd: window,
                    guidItem: guid,
                    ..Default::default()
                },
            );
        });
        // Enable better callback API.
        Shell_NotifyIconW(NIM_SETVERSION, notify_icon_data).ok()?;
        let rect = Shell_NotifyIconGetRect(&mut NOTIFYICONIDENTIFIER {
            cbSize: std::mem::size_of::<NOTIFYICONIDENTIFIER>() as u32,
            guidItem: guid,
            ..Default::default()
        })?;
        debug!("Taskbar icon rect: {:?}", rect);

        info!("Running...");
        loop {
            let mut msg = MSG::default();
            debug!("Waiting for message...");
            GetMessageW(&mut msg, None, 0, 0).ok()?;
            debug!("Message received: {:#x} {:?}", msg.message, msg);
            debug!("dispatching message: {:?}", msg);
            DispatchMessageW(&msg);
        }
    }
}

unsafe fn create_popup_menu() -> Result<HMENU, Box<dyn Error>> {
    let menu = CreatePopupMenu()?;
    debug!("Popup menu created: {:?}", menu);
    let mut item = MENUITEMINFOW {
        cbSize: std::mem::size_of::<MENUITEMINFOW>() as u32,
        fMask: MIIM_FTYPE | MIIM_STATE | MIIM_STRING | MIIM_CHECKMARKS,
        fType: MFT_STRING,
        dwTypeData: PWSTR("Enable\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr()),
        cch: "Enable".len() as u32,
        fState: MFS_ENABLED | MFS_CHECKED,
        ..Default::default()
    };
    InsertMenuItemW(menu, 0, true, &mut item)?;
    Ok(menu)
}

const UNCAPPY_INFO: usize = (WM_APP + 0x4242) as usize;

unsafe extern "system" fn window_callback(
    hwnd: windows::Win32::Foundation::HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    debug!(
        "Window callback: hwnd={:?}, msg={:#x}, wparam={:#x}, lparam={:#x}",
        hwnd, msg, wparam.0, lparam.0
    );
    // GWLP_USERDATA contains a pointer to an Uncappy instance but may not be set yet during window creation messages.
    match msg {
        UNCAPPY_TASKBAR_CB_ID => {
            debug!("Taskbar icon message received");
            let uncappy = &*(GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const Uncappy);
            match LOWORD(lparam.0) as u32 {
                WM_LBUTTONUP => {
                    debug!("Mouse click received");
                }
                WM_RBUTTONUP => {
                    debug!("Right click received");
                    let mut cursor_pos = POINT::default();
                    GetCursorPos(&mut cursor_pos).unwrap();
                    match uncappy.show_popup_menu(cursor_pos.x, cursor_pos.y) {
                        Ok(_) => {
                            debug!("Popup menu shown");
                        }
                        Err(err) => {
                            error!("Failed to show popup menu: {:?}", err);
                        }
                    }
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_COMMAND => {
            debug!("Command received");
            let uncappy = &*(GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const Uncappy);
            let chosen = LOWORD(wparam.0 as isize) as u32;
            let _ = uncappy.menu_selection(chosen);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
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
