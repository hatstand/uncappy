use defer::defer;
use std::error::Error;
use windows::Win32::Foundation::{GetLastError, LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP,
    VIRTUAL_KEY, VK_CAPITAL, VK_ESCAPE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, GetMessageW, SetWindowsHookExA, UnhookWindowsHookEx, KBDLLHOOKSTRUCT,
    WH_KEYBOARD_LL, WM_APP, WM_KEYUP, WM_SYSKEYUP,
};
use windows_core::BOOL;

fn main() -> Result<(), Box<dyn Error>> {
    println!("Hello, world!");

    // unsafe
    //     let hook_id = user32::SetWindowsHookExA(
    //         winapi::um::winuser::WH_KEYBOARD_LL,
    //         Some(hook_callback),
    //         std::ptr::null_mut(),
    //         0,
    //     );
    //     defer!({
    //         user32::UnhookWindowsHookEx(hook_id);
    //     });

    //     let mut msg: winapi::winuser::MSG = std::mem::zeroed();
    //     while user32::GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) != 0 {}
    // }
    unsafe {
        let hook_id = SetWindowsHookExA(WH_KEYBOARD_LL, Some(hook_callback), None, 0)?;
        defer!({
            let _ = UnhookWindowsHookEx(hook_id);
        });
        match GetMessageW(std::ptr::null_mut(), None, 0, 0) {
            BOOL(1) => {
                println!("Message received");
            }
            _ => {
                println!("No message");
            }
        }
    }
    Ok(())
}

const UNCAPPY_INFO: usize = (WM_APP + 424242) as usize;

unsafe extern "system" fn hook_callback(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    println!(
        "Hook callback triggered {:?} {:?} {:?}",
        code, wparam, lparam
    );
    let p: &KBDLLHOOKSTRUCT = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
    println!("Key: {:?}", p.vkCode);

    let key_code = VIRTUAL_KEY(p.vkCode as u16);
    match key_code {
        VK_CAPITAL => {
            println!("Caps Lock pressed");
            if p.dwExtraInfo == UNCAPPY_INFO {
                println!("Uncappy event");
                return LRESULT(1);
            }
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
                1 => {
                    println!("Key remapped successfully");
                }
                0 => {
                    println!("Failed to remap key: {:?}", GetLastError());
                }
                n => {
                    println!("Failed to remap key: {:?}", n);
                }
            }
            LRESULT(1)
        }
        _ => {
            println!("Other key pressed");
            CallNextHookEx(None, code, wparam, lparam)
        }
    }
}
