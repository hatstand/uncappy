#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use defer::defer;
use log::{debug, error, info};
use std::cell::RefCell;
use std::collections::HashMap;
use std::error::Error;
use std::ptr::null_mut;
use std::thread_local;
use windows::Win32::Foundation::{GetLastError, HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP,
    VIRTUAL_KEY, VK_CAPITAL, VK_ESCAPE,
};
use windows::Win32::UI::Shell::{
    ShellExecuteW, Shell_NotifyIconW, NIF_GUID, NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP,
    NIM_ADD, NIM_DELETE, NIM_MODIFY, NIM_SETVERSION, NIN_SELECT, NOTIFYICONDATAW,
    NOTIFYICONDATAW_0, NOTIFYICON_VERSION_4,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyIcon,
    DispatchMessageW, GetCursorPos, GetMenuItemInfoW, GetMessageW, InsertMenuItemW, LoadIconW,
    PostMessageW, PostQuitMessage, RegisterClassExW, SetForegroundWindow, SetMenuItemInfoW,
    SetWindowsHookExA, TrackPopupMenuEx, UnhookWindowsHookEx, UnregisterClassW, HICON, HMENU,
    KBDLLHOOKSTRUCT, MENUITEMINFOW, MENU_ITEM_STATE, MFS_CHECKED, MFS_DISABLED, MFS_ENABLED,
    MFT_SEPARATOR, MFT_STRING, MIIM_CHECKMARKS, MIIM_FTYPE, MIIM_ID, MIIM_STATE, MIIM_STRING, MSG,
    SW_SHOWNORMAL, TPM_BOTTOMALIGN, TPM_LEFTALIGN, TPM_RIGHTBUTTON, WH_KEYBOARD_LL,
    WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_CLOSE, WM_COMMAND, WM_DESTROY, WM_KEYUP, WM_QUIT,
    WM_RBUTTONUP, WM_SYSKEYUP, WNDCLASSEXW,
};
use windows_core::{BOOL, GUID, PCWSTR, PWSTR};

const UNCAPPY_TASKBAR_CB_ID: u32 = WM_APP + 1;

#[allow(non_snake_case)]
pub fn LOWORD(l: isize) -> isize {
    l & 0xffff
}

#[allow(non_snake_case)]
pub fn HIWORD(l: isize) -> isize {
    (l >> 16) & 0xffff
}

#[allow(non_snake_case)]
pub fn GET_X_LPARAM(l: usize) -> i32 {
    (l & 0xffff) as i32
}

#[allow(non_snake_case)]
pub fn GET_Y_LPARAM(l: usize) -> i32 {
    ((l >> 16) & 0xffff) as i32
}

const POPUP_ENABLE_ID: u32 = 0x42;
const POPUP_EXIT_ID: u32 = 0x43;
const POPUP_ABOUT_ID: u32 = 0x44;

#[derive(PartialEq, Eq, Debug)]
enum Mapping {
    MapCapsToEscape,
    DisableMapping,
}

struct Uncappy {
    instance: HINSTANCE,
    window: HWND,
    popup_menu: HMENU,
    mapping: Mapping,
    guid: GUID,
    icon_cache: HashMap<String, HICON>,
}

const TOOLTIP_ENABLED: &str = "Mapping Caps Lock to Escape";
const TOOLTIP_DISABLED: &str = "Mapping disabled";

thread_local! {
    // The low-level keyboard hook has no way to receive user data.
    // Fortunately, it should be called from the same thread as it was created in so we can rely on thread-local storage.
    static UNCAPPY: RefCell<Option<Uncappy>> = const { RefCell::new(None) };
}

fn toggle_checked(current_state: MENU_ITEM_STATE) -> MENU_ITEM_STATE {
    if current_state & MFS_CHECKED == MFS_CHECKED {
        current_state & !MFS_CHECKED
    } else {
        current_state | MFS_CHECKED
    }
}

fn icon_for_mapping(mapping: &Mapping) -> String {
    match mapping {
        Mapping::MapCapsToEscape => "exit_icon".to_string(),
        Mapping::DisableMapping => "noexit_icon".to_string(),
    }
}

impl Drop for Uncappy {
    fn drop(&mut self) {
        unsafe {
            self.icon_cache.iter().for_each(|(_, icon)| {
                let _ = DestroyIcon(*icon);
            });
        }
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

    fn menu_selection(&mut self, id: u32) -> Result<(), Box<dyn Error>> {
        debug!("Menu item selected: {}", id);
        unsafe {
            match id {
                POPUP_EXIT_ID => {
                    debug!("Exit selected");
                    PostMessageW(
                        Some(self.window),
                        WM_CLOSE,
                        WPARAM::default(),
                        LPARAM::default(),
                    )?;
                }
                POPUP_ENABLE_ID => {
                    debug!("Enable/Disable selected");
                    self.toggle()?;
                }
                POPUP_ABOUT_ID => {
                    debug!("About selected");
                    ShellExecuteW(
                        None,
                        PCWSTR(null_mut()),
                        to_pcwstr("https://github.com/hatstand/uncappy"),
                        PCWSTR(null_mut()),
                        PCWSTR(null_mut()),
                        SW_SHOWNORMAL,
                    );
                }
                _ => {
                    debug!("Unknown menu item selected: {}", id);
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    unsafe fn load_icon(&mut self, icon_name: &str) -> Result<HICON, Box<dyn Error>> {
        if let Some(icon) = self.icon_cache.get(icon_name) {
            debug!("Icon found in cache: {:?}", icon);
            return Ok(*icon);
        }
        debug!("Loading icon: {}", icon_name);
        let icon = LoadIconW(Some(self.instance), to_pcwstr(icon_name))?;
        self.icon_cache.insert(icon_name.to_string(), icon);
        Ok(icon)
    }

    unsafe fn toggle(&mut self) -> Result<(), Box<dyn Error>> {
        self.mapping = match self.mapping {
            Mapping::MapCapsToEscape => Mapping::DisableMapping,
            Mapping::DisableMapping => Mapping::MapCapsToEscape,
        };
        debug!("Mapping toggling to: {:?}", self.mapping);

        debug!("Updating menu item state");
        let mut mii = MENUITEMINFOW {
            cbSize: std::mem::size_of::<MENUITEMINFOW>() as u32,
            fMask: MIIM_STATE,
            ..Default::default()
        };
        GetMenuItemInfoW(self.popup_menu, POPUP_ENABLE_ID, false, &mut mii)?;
        debug!("Menu check state: {:?}", mii.fState & MFS_CHECKED);
        mii.fMask = MIIM_STATE;
        mii.fState = toggle_checked(mii.fState);
        SetMenuItemInfoW(self.popup_menu, POPUP_ENABLE_ID, false, &mii)?;

        let icon_name = icon_for_mapping(&self.mapping);
        debug!("Swapping icon to: {}", icon_name);
        let icon = self.load_icon(&icon_name)?;
        debug!("Icon loaded: {:?}", icon);
        Shell_NotifyIconW(
            NIM_MODIFY,
            &NOTIFYICONDATAW {
                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: self.window,
                uFlags: NIF_ICON | NIF_GUID | NIF_TIP | NIF_SHOWTIP,
                guidItem: self.guid,
                szTip: string_to_tip(if self.mapping == Mapping::MapCapsToEscape {
                    TOOLTIP_ENABLED
                } else {
                    TOOLTIP_DISABLED
                }),
                hIcon: icon,
                ..Default::default()
            },
        )
        .ok()?;
        Ok(())
    }

    // With reference to https://github.com/susam/uncap
    unsafe fn ll_keyboard_hook(&self, ncode: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        if ncode < 0 {
            return CallNextHookEx(None, ncode, wparam, lparam);
        }
        if self.mapping == Mapping::DisableMapping {
            // No remapping needed.
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
                CallNextHookEx(None, ncode, wparam, lparam)
            }
        }
    }
}

fn string_to_tip(s: &str) -> [u16; 128] {
    let mut ret = [0u16; 128];
    let encoded: Vec<u16> = s.encode_utf16().collect();
    assert!(encoded.len() < ret.len());
    for (i, &c) in encoded.iter().enumerate() {
        ret[i] = c;
    }
    ret[encoded.len()] = 0; // Null-terminate the string
    ret
}

fn to_pcwstr(s: &str) -> PCWSTR {
    let mut v = s.encode_utf16().collect::<Vec<u16>>();
    v.push(0);
    PCWSTR(v.as_ptr())
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let version: &str = option_env!("VERSION").unwrap_or("unknown");
    info!("Uncappy version: {}", version);
    unsafe {
        let module = GetModuleHandleW(None)?;
        // Register a window class for the taskbar icon.
        let class_name = to_pcwstr("Uncappy");
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
            to_pcwstr("Uncappy Window"),
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

        let guid = GUID::new()?;
        UNCAPPY.set(Some(Uncappy {
            instance: module.into(),
            window,
            popup_menu: create_popup_menu()?,
            mapping: Mapping::MapCapsToEscape,
            guid,
            icon_cache: HashMap::new(),
        }));

        // Register a low-level keyboard hook that receives all keyboard events on the system.
        let hook_id = SetWindowsHookExA(WH_KEYBOARD_LL, Some(hook_callback), None, 0)?;
        defer!({
            let _ = UnhookWindowsHookEx(hook_id);
        });

        debug!("Loading icon");
        let icon =
            UNCAPPY.with_borrow_mut(|uncappy| uncappy.as_mut().unwrap().load_icon("exit_icon"))?;
        debug!("adding to taskbar");
        let notify_icon_data = &mut NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: window,
            hIcon: icon,
            guidItem: guid,
            // Both NIF_TIP & NIF_SHOWTIP are required to actually show the tooltip.
            uFlags: NIF_ICON | NIF_MESSAGE | NIF_GUID | NIF_TIP | NIF_SHOWTIP,
            uCallbackMessage: UNCAPPY_TASKBAR_CB_ID,
            szTip: string_to_tip(TOOLTIP_ENABLED),
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
                &NOTIFYICONDATAW {
                    cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                    uFlags: NIF_GUID,
                    hWnd: window,
                    guidItem: guid,
                    ..Default::default()
                },
            );
        });
        // Enable better callback API.
        Shell_NotifyIconW(NIM_SETVERSION, notify_icon_data).ok()?;

        // Enter the message loop.
        info!("Running...");
        loop {
            let mut msg = MSG::default();
            debug!("Waiting for message...");
            match GetMessageW(&mut msg, None, 0, 0) {
                BOOL(0) => {
                    assert_eq!(msg.message, WM_QUIT);
                    info!("Quitting...");
                    break;
                }
                BOOL(-1) => {
                    error!("Failed to get message: {:?}", GetLastError());
                }
                BOOL(_) => {
                    DispatchMessageW(&msg);
                }
            }
        }
        Ok(())
    }
}

unsafe fn create_popup_menu() -> Result<HMENU, Box<dyn Error>> {
    let menu = CreatePopupMenu()?;
    debug!("Popup menu created: {:?}", menu);
    // Add a menu item to exit the application.
    InsertMenuItemW(
        menu,
        0,
        true,
        &MENUITEMINFOW {
            cbSize: std::mem::size_of::<MENUITEMINFOW>() as u32,
            fMask: MIIM_FTYPE | MIIM_ID | MIIM_STRING,
            fType: MFT_STRING,
            dwTypeData: PWSTR("Exit\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr()),
            cch: "Exit".len() as u32,
            wID: POPUP_EXIT_ID,
            ..Default::default()
        },
    )?;
    // Add a menu item to toggle the Caps Lock key mapping.
    InsertMenuItemW(
        menu,
        0,
        true,
        &MENUITEMINFOW {
            cbSize: std::mem::size_of::<MENUITEMINFOW>() as u32,
            fMask: MIIM_FTYPE | MIIM_STATE | MIIM_STRING | MIIM_CHECKMARKS | MIIM_ID,
            fType: MFT_STRING,
            dwTypeData: PWSTR("Enable\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr()),
            cch: "Enable".len() as u32,
            fState: MFS_ENABLED | MFS_CHECKED,
            wID: POPUP_ENABLE_ID,
            ..Default::default()
        },
    )?;
    // Add a separator.
    InsertMenuItemW(
        menu,
        0,
        true,
        &MENUITEMINFOW {
            cbSize: std::mem::size_of::<MENUITEMINFOW>() as u32,
            fMask: MIIM_FTYPE,
            fType: MFT_SEPARATOR,
            ..Default::default()
        },
    )?;
    // Add a menu item for the about dialog.
    InsertMenuItemW(
        menu,
        0,
        true,
        &MENUITEMINFOW {
            cbSize: std::mem::size_of::<MENUITEMINFOW>() as u32,
            fMask: MIIM_FTYPE | MIIM_ID | MIIM_STRING,
            fType: MFT_STRING,
            dwTypeData: PWSTR("About\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr()),
            cch: "About".len() as u32,
            wID: POPUP_ABOUT_ID,
            ..Default::default()
        },
    )?;
    // Add a nice name to the top of the menu.
    InsertMenuItemW(
        menu,
        0,
        true,
        &MENUITEMINFOW {
            cbSize: std::mem::size_of::<MENUITEMINFOW>() as u32,
            fMask: MIIM_FTYPE | MIIM_STATE | MIIM_STRING,
            fType: MFT_STRING,
            dwTypeData: PWSTR(
                "Uncappy\0"
                    .encode_utf16()
                    .collect::<Vec<u16>>()
                    .as_mut_ptr(),
            ),
            cch: "Uncappy".len() as u32,
            fState: MFS_DISABLED,
            ..Default::default()
        },
    )?;
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
    match msg {
        UNCAPPY_TASKBAR_CB_ID => {
            debug!("Taskbar icon message received: {:#x}", LOWORD(lparam.0));
            match LOWORD(lparam.0) as u32 {
                WM_RBUTTONUP => {
                    debug!("Right click received");
                    let mut cursor_pos = POINT::default();
                    GetCursorPos(&mut cursor_pos).unwrap();
                    UNCAPPY.with_borrow(|uncappy| {
                        match uncappy
                            .as_ref()
                            .unwrap()
                            .show_popup_menu(cursor_pos.x, cursor_pos.y)
                        {
                            Ok(_) => {
                                debug!("Popup menu shown");
                            }
                            Err(err) => {
                                error!("Failed to show popup menu: {:?}", err);
                            }
                        }
                    });
                    LRESULT(0)
                }
                NIN_SELECT => {
                    debug!("NIN_SELECT");
                    UNCAPPY.with_borrow_mut(|uncappy| match uncappy.as_mut().unwrap().toggle() {
                        Ok(_) => {
                            debug!("Mapping toggled");
                        }
                        Err(err) => {
                            error!("Failed to toggle mapping: {:?}", err);
                        }
                    });
                    LRESULT(0)
                }
                _ => DefWindowProcW(hwnd, msg, wparam, lparam),
            }
        }
        WM_COMMAND => {
            debug!("Menu Command received");
            let chosen = LOWORD(wparam.0 as isize) as u32;
            UNCAPPY.with_borrow_mut(|uncappy| {
                let _ = uncappy.as_mut().unwrap().menu_selection(chosen);
            });
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

unsafe extern "system" fn hook_callback(ncode: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    UNCAPPY.with_borrow(|uncappy| {
        uncappy
            .as_ref()
            .unwrap()
            .ll_keyboard_hook(ncode, wparam, lparam)
    })
}
