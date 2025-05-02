use defer::defer;
use log::{debug, error, info};
use std::error::Error;
use windows::Win32::Foundation::{GetLastError, LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP,
    VIRTUAL_KEY, VK_CAPITAL, VK_ESCAPE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, GetMessageW, SetWindowsHookExA, UnhookWindowsHookEx, KBDLLHOOKSTRUCT, MSG,
    WH_KEYBOARD_LL, WM_APP, WM_KEYUP, WM_SYSKEYUP,
};

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    unsafe {
        // Register a low-level keyboard hook that receives all keyboard events on the system.
        let hook_id = SetWindowsHookExA(WH_KEYBOARD_LL, Some(hook_callback), None, 0)?;
        defer!({
            let _ = UnhookWindowsHookEx(hook_id);
        });
        info!("Running...");
        let mut msg = MSG::default();
        let _ = GetMessageW(&mut msg, None, 0, 0);
    }
    Ok(())
}

const UNCAPPY_INFO: usize = (WM_APP + 424242) as usize;

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
