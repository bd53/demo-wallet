use std::sync::mpsc;
use super::super::app::WalletGui;

pub fn handle_pending_results(app: &mut WalletGui) {
    handle_gen_rx(app);
    handle_verify_rx(app);
    handle_addr_rx(app);
    handle_derive_rx(app);
    handle_export_rx(app);
    handle_restore_rx(app);
    handle_change_pwd_rx(app);
    handle_delete_rx(app);
}

fn handle_gen_rx(app: &mut WalletGui) {
    if let Some(rx) = app.gen_rx.take() {
        match rx.try_recv() {
            Ok(result) => {
                app.is_processing = false;
                match result {
                    Ok(_) => {
                        app.set_status_ok("Wallet generated successfully.");
                        app.refresh_wallet_status();
                        app.password.clear();
                    }
                    Err(e) => app.set_error(&format!("Generation failed: {}", e)),
                }
            }
            Err(mpsc::TryRecvError::Empty) => {
                app.gen_rx = Some(rx);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_processing = false;
                app.set_error("Generation thread disconnected.");
            }
        }
    }
}

fn handle_verify_rx(app: &mut WalletGui) {
    if let Some(rx) = app.verify_rx.take() {
        match rx.try_recv() {
            Ok(result) => {
                app.is_processing = false;
                match result {
                    Ok(info) => {
                        app.wallet_loaded = true;
                        app.set_status_ok("Wallet verified successfully.");
                        app.wallet_info = Some(info);
                    }
                    Err(e) => {
                        app.wallet_loaded = false;
                        app.set_error(&format!("Verification failed: {}", e));
                        app.wallet_info = None;
                    }
                }
            }
            Err(mpsc::TryRecvError::Empty) => {
                app.verify_rx = Some(rx);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_processing = false;
                app.set_error("Verification thread disconnected.");
            }
        }
    }
}

fn handle_addr_rx(app: &mut WalletGui) {
    if let Some(rx) = app.addr_rx.take() {
        match rx.try_recv() {
            Ok(result) => {
                app.is_processing = false;
                match result {
                    Ok((addrs, qr_imgs)) => {
                        app.addresses = Some(addrs);
                        if let Some(qr) = qr_imgs {
                            app.qr_images = qr;
                        }
                        app.set_status_ok(&format!("Addresses loaded (Account {}).", app.account_index));
                    }
                    Err(e) => {
                        app.set_error(&format!("Failed to load addresses: {}", e));
                        app.addresses = None;
                        app.qr_images = super::super::state::QrImages::default();
                    }
                }
            }
            Err(mpsc::TryRecvError::Empty) => {
                app.addr_rx = Some(rx);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_processing = false;
                app.set_error("Address loading thread disconnected.");
            }
        }
    }
}

fn handle_derive_rx(app: &mut WalletGui) {
    if let Some(rx) = app.derive_rx.take() {
        match rx.try_recv() {
            Ok(result) => {
                app.is_processing = false;
                match result {
                    Ok(accounts) => {
                        app.derived_accounts = accounts;
                        app.set_status_ok(&format!("Derived ({}) accounts successfully.", app.derive_count));
                        app.password.clear();
                    }
                    Err(e) => app.set_error(&format!("Failed to derive accounts: {}", e)),
                }
            }
            Err(mpsc::TryRecvError::Empty) => {
                app.derive_rx = Some(rx);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_processing = false;
                app.set_error("Derivation thread disconnected.");
            }
        }
    }
}

fn handle_export_rx(app: &mut WalletGui) {
    if let Some(rx) = app.export_rx.take() {
        match rx.try_recv() {
            Ok(result) => {
                app.is_processing = false;
                match result {
                    Ok(_) => app.set_status_ok("Data exported successfully."),
                    Err(e) => app.set_error(&format!("Export failed: {}", e)),
                }
            }
            Err(mpsc::TryRecvError::Empty) => {
                app.export_rx = Some(rx);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_processing = false;
                app.set_error("Export thread disconnected.");
            }
        }
    }
}

fn handle_restore_rx(app: &mut WalletGui) {
    if let Some(rx) = app.restore_rx.take() {
        match rx.try_recv() {
            Ok(result) => {
                app.is_processing = false;
                match result {
                    Ok(_) => {
                        app.set_status_ok("Wallet restored successfully.");
                        app.refresh_wallet_status();
                        app.restore_mnemonic.clear();
                        app.restore_password.clear();
                        app.restore_share_paths.clear();
                    }
                    Err(e) => app.set_error(&format!("Restore failed: {}", e)),
                }
            }
            Err(mpsc::TryRecvError::Empty) => {
                app.restore_rx = Some(rx);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_processing = false;
                app.set_error("Restore thread disconnected.");
            }
        }
    }
}

fn handle_change_pwd_rx(app: &mut WalletGui) {
    if let Some(rx) = app.change_pwd_rx.take() {
        match rx.try_recv() {
            Ok(result) => {
                app.is_processing = false;
                match result {
                    Ok(_) => {
                        app.set_status_ok("Password changed successfully.");
                        app.old_password.clear();
                        app.new_password.clear();
                    }
                    Err(e) => app.set_error(&format!("Password change failed: {}", e)),
                }
            }
            Err(mpsc::TryRecvError::Empty) => {
                app.change_pwd_rx = Some(rx);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_processing = false;
                app.set_error("Password change thread disconnected.");
            }
        }
    }
}

fn handle_delete_rx(app: &mut WalletGui) {
    if let Some(rx) = app.delete_rx.take() {
        match rx.try_recv() {
            Ok(result) => {
                app.is_processing = false;
                match result {
                    Ok(_) => {
                        app.set_status_ok("Wallet deleted successfully.");
                        app.refresh_wallet_status();
                        app.addresses = None;
                        app.wallet_info = None;
                        app.wallet_loaded = false;
                    }
                    Err(e) => app.set_error(&format!("Deletion failed: {}", e)),
                }
            }
            Err(mpsc::TryRecvError::Empty) => {
                app.delete_rx = Some(rx);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_processing = false;
                app.set_error("Deletion thread disconnected.");
            }
        }
    }
}
