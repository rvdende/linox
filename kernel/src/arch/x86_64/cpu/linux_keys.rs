use super::*;

fn linux_key_error(error: crate::linux_keyring::Error) -> u64 {
    (-i64::from(error.errno())) as u64
}

/// Runs `operation` on the domain's keys for the calling thread: its
/// filesystem ids own and access keys, its real ids pick the user keyrings,
/// and it acts for other users (CAP_SYS_ADMIN) only where the domain lets
/// root switch users.
pub(super) fn linux_with_keys<R>(
    operation: impl FnOnce(
        &mut crate::linux_keyring::Keyrings,
        &crate::linux_keyring::Caller,
    ) -> Result<R, crate::linux_keyring::Error>,
) -> Result<R, u64> {
    let pid = current_linux_process_pid();
    let tid = current_linux_tid().unwrap_or(pid);
    let credentials = current_linux_credentials().unwrap_or(linux_user::Credentials::ROOT);
    let privileged = current_linux_user_namespace().is_some_and(|namespace| {
        linux_user::identity_authority(namespace, &credentials).privileged
    });
    let groups = linux_process::with_live_process_groups(pid, |groups| {
        let mut copy = Vec::new();
        copy.try_reserve_exact(groups.len()).ok()?;
        copy.extend_from_slice(groups);
        Some(copy)
    })
    .flatten()
    .unwrap_or_default();
    let caller = crate::linux_keyring::Caller {
        uid: credentials.user.filesystem,
        gid: credentials.group.filesystem,
        groups: &groups,
        real_uid: credentials.user.real,
        real_gid: credentials.group.real,
        pid,
        tid,
        privileged,
    };
    let limits = linux_key_limits();
    let now = linux_key_clock();
    let gc_delay = linux_proc_sysctl_value(b"sys/kernel/keys/gc_delay")
        .and_then(|seconds| u64::try_from(seconds).ok())
        .unwrap_or(LINUX_KEY_GC_DELAY_SECONDS)
        .saturating_mul(NANOSECONDS_PER_SECOND);
    crate::linux_keyring::with(|keys| {
        keys.set_limits(limits)?;
        keys.collect_garbage(now, gc_delay);
        operation(keys, &caller)
    })
    .map_err(linux_key_error)
}

/// Linux's default /proc/sys/kernel/keys/gc_delay.
const LINUX_KEY_GC_DELAY_SECONDS: u64 = 300;

/// Process `pid` ended: its threads' and its own keyrings go, as Linux
/// drops them with the tasks' credentials, and keys only they kept leave
/// their owners' quotas. Skipped (left to the next fork that reuses the
/// id) when a lock ranked above the keys' is held.
pub(super) fn release_linux_process_keys(pid: u32) {
    crate::linux_path_views::forget(linux_execution_instance(), pid);
    if crate::sync::rank_available(crate::sync::LockRank::KEYRINGS) {
        let _ = crate::linux_keyring::with(|keys| {
            keys.exit_process(pid);
            Ok(())
        });
    }
}

/// The domain's key quotas: /proc/sys/kernel/keys as written, else Linux's
/// defaults.
fn linux_key_limits() -> linox_keyrings::Limits {
    let defaults = linox_keyrings::Limits::LINUX;
    let value = |path: &[u8], default: u32| {
        linux_proc_sysctl_value(path)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(default)
    };
    linox_keyrings::Limits {
        root_max_keys: value(b"sys/kernel/keys/root_maxkeys", defaults.root_max_keys),
        root_max_bytes: value(b"sys/kernel/keys/root_maxbytes", defaults.root_max_bytes),
        max_keys: value(b"sys/kernel/keys/maxkeys", defaults.max_keys),
        max_bytes: value(b"sys/kernel/keys/maxbytes", defaults.max_bytes),
    }
}

/// The kernel clock the key service measures timeouts with.
pub(super) fn linux_key_clock() -> u64 {
    linux_elapsed_nanoseconds().unwrap_or(0)
}

/// Copies a NUL-terminated key argument that fits in `limit` bytes with its
/// NUL; a longer one is EINVAL, as Linux's strndup_user makes it.
fn linux_key_string(address: u64, limit: usize) -> Result<Vec<u8>, u64> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(limit).map_err(|_| LINUX_ENOMEM)?;
    buffer.resize(limit, 0);
    match copy_linux_c_string(address, &mut buffer) {
        Ok(length) => {
            buffer.truncate(length);
            Ok(buffer)
        }
        Err(LINUX_ENAMETOOLONG) => Err(LINUX_EINVAL),
        Err(error) => Err(error),
    }
}

/// Copies a key type name, refusing reserved names (EPERM) before any later
/// argument is read, as Linux does.
fn linux_key_type(address: u64) -> Result<Vec<u8>, u64> {
    let name = linux_key_string(address, linox_keyrings::TYPE_LIMIT)?;
    linox_keyrings::check_type_name(&name).map_err(linux_key_error)?;
    Ok(name)
}

/// Copies `length` bytes of key payload from `address`.
fn linux_key_payload(address: u64, length: usize) -> Result<Vec<u8>, u64> {
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(length)
        .map_err(|_| LINUX_ENOMEM)?;
    payload.resize(length, 0);
    if length != 0 && !copy_from_linux_user(address, &mut payload) {
        return Err(LINUX_EFAULT);
    }
    Ok(payload)
}

/// Copies what `output` gives a buffer of `capacity` bytes at `address`
/// (nothing for a null buffer) and returns the output's full length.
fn linux_key_output(output: &crate::linux_keyring::Output, address: u64, capacity: u64) -> u64 {
    let bytes = if address == 0 {
        &[][..]
    } else {
        output.for_buffer(usize::try_from(capacity).unwrap_or(usize::MAX))
    };
    if !bytes.is_empty() && !copy_to_linux_user(address, bytes) {
        return LINUX_EFAULT;
    }
    output.len() as u64
}

pub(super) fn linux_add_key(
    type_address: u64,
    description_address: u64,
    payload_address: u64,
    payload_length: u64,
    keyring: u64,
) -> u64 {
    let Some(payload_length) = usize::try_from(payload_length)
        .ok()
        .filter(|length| *length <= linox_keyrings::PAYLOAD_LIMIT)
    else {
        return LINUX_EINVAL;
    };
    let added = (|| {
        let key_type = linux_key_type(type_address)?;
        let description = if description_address == 0 {
            Vec::new()
        } else {
            linux_key_string(description_address, linox_keyrings::DESCRIPTION_LIMIT)?
        };
        if key_type == b"keyring" && description.first() == Some(&b'.') {
            return Err(LINUX_EPERM);
        }
        let payload = linux_key_payload(payload_address, payload_length)?;
        let now = linux_key_clock();
        linux_with_keys(|keys, caller| {
            keys.add_key(
                caller,
                &key_type,
                &description,
                &payload,
                keyring as i32,
                now,
            )
        })
    })();
    added.map_or_else(|error| error, |serial| serial as u64)
}

pub(super) fn linux_request_key(
    type_address: u64,
    description_address: u64,
    callout_address: u64,
    destination: u64,
) -> u64 {
    let requested = (|| {
        let key_type = linux_key_type(type_address)?;
        let description = linux_key_string(description_address, linox_keyrings::DESCRIPTION_LIMIT)?;
        let callout = if callout_address == 0 {
            None
        } else {
            Some(linux_key_string(
                callout_address,
                linox_keyrings::CALLOUT_LIMIT,
            )?)
        };
        let now = linux_key_clock();
        linux_with_keys(|keys, caller| {
            keys.request_key(
                caller,
                &key_type,
                &description,
                callout.as_deref(),
                destination as i32,
                now,
            )
        })
    })();
    requested.map_or_else(|error| error, |serial| serial as u64)
}

pub(super) fn linux_keyctl(command: u64, second: u64, third: u64, fourth: u64, fifth: u64) -> u64 {
    const GET_KEYRING_ID: u64 = 0;
    const JOIN_SESSION_KEYRING: u64 = 1;
    const UPDATE: u64 = 2;
    const REVOKE: u64 = 3;
    const CHOWN: u64 = 4;
    const SETPERM: u64 = 5;
    const DESCRIBE: u64 = 6;
    const CLEAR: u64 = 7;
    const LINK: u64 = 8;
    const UNLINK: u64 = 9;
    const SEARCH: u64 = 10;
    const READ: u64 = 11;
    const INSTANTIATE: u64 = 12;
    const NEGATE: u64 = 13;
    const SET_REQKEY_KEYRING: u64 = 14;
    const SET_TIMEOUT: u64 = 15;
    const ASSUME_AUTHORITY: u64 = 16;
    const GET_SECURITY: u64 = 17;
    const SESSION_TO_PARENT: u64 = 18;
    const REJECT: u64 = 19;
    const INSTANTIATE_IOV: u64 = 20;
    const INVALIDATE: u64 = 21;
    const DH_COMPUTE: u64 = 23;
    const PKEY_QUERY: u64 = 24;
    const RESTRICT_KEYRING: u64 = 29;
    const MOVE: u64 = 30;
    const CAPABILITIES: u64 = 31;
    let id = second as i32;
    let now = linux_key_clock();
    let unit = |result: Result<(), u64>| result.map_or_else(|error| error, |()| 0);
    let serial = |result: Result<i32, u64>| result.map_or_else(|error| error, |id| id as u64);
    let output = |result: Result<crate::linux_keyring::Output, u64>| {
        result.map_or_else(
            |error| error,
            |output| linux_key_output(&output, third, fourth),
        )
    };
    match command {
        GET_KEYRING_ID => serial(linux_with_keys(|keys, caller| {
            keys.get_keyring_id(caller, id, third as i32 != 0, now)
        })),
        JOIN_SESSION_KEYRING => serial((|| {
            let name = if second == 0 {
                None
            } else {
                Some(linux_key_string(second, linox_keyrings::DESCRIPTION_LIMIT)?)
            };
            linux_with_keys(|keys, caller| keys.join_session_keyring(caller, name.as_deref()))
        })()),
        UPDATE => unit((|| {
            let length = usize::try_from(fourth)
                .ok()
                .filter(|length| *length <= linox_keyrings::UPDATE_LIMIT)
                .ok_or(LINUX_EINVAL)?;
            let payload = linux_key_payload(third, length)?;
            linux_with_keys(|keys, caller| keys.update(caller, id, &payload, now))
        })()),
        REVOKE => unit(linux_with_keys(|keys, caller| keys.revoke(caller, id, now))),
        CHOWN => {
            let change = |raw: u64| (raw as u32 != u32::MAX).then_some(raw as u32);
            unit(linux_with_keys(|keys, caller| {
                keys.chown(caller, id, change(third), change(fourth), now)
            }))
        }
        SETPERM => unit(linux_with_keys(|keys, caller| {
            keys.set_permissions(caller, id, third as u32, now)
        })),
        DESCRIBE => output(linux_with_keys(|keys, caller| {
            keys.describe(caller, id, now)
        })),
        CLEAR => unit(linux_with_keys(|keys, caller| keys.clear(caller, id, now))),
        LINK => unit(linux_with_keys(|keys, caller| {
            keys.link(caller, id, third as i32, now)
        })),
        UNLINK => unit(linux_with_keys(|keys, caller| {
            keys.unlink(caller, id, third as i32, now)
        })),
        SEARCH => serial((|| {
            let key_type = linux_key_type(third)?;
            let description = linux_key_string(fourth, linox_keyrings::DESCRIPTION_LIMIT)?;
            linux_with_keys(|keys, caller| {
                keys.search(caller, id, &key_type, &description, fifth as i32, now)
            })
        })()),
        READ => {
            let capacity = if third == 0 {
                0
            } else {
                usize::try_from(fourth).unwrap_or(usize::MAX)
            };
            output(linux_with_keys(|keys, caller| {
                keys.read_into(caller, id, capacity, now)
            }))
        }
        INSTANTIATE | NEGATE | REJECT | INSTANTIATE_IOV => LINUX_EPERM,
        SET_REQKEY_KEYRING => serial(linux_with_keys(|keys, caller| {
            keys.set_request_default(caller, id)
        })),
        SET_TIMEOUT => unit(linux_with_keys(|keys, caller| {
            keys.set_timeout(caller, id, third as u32, now)
        })),
        // No upcalls, so there is never an authorization key to assume.
        ASSUME_AUTHORITY => match id {
            0 => 0,
            id if id < 0 => LINUX_EINVAL,
            _ => LINUX_ENOKEY,
        },
        GET_SECURITY => output(linux_with_keys(|keys, caller| {
            keys.get_security(caller, id, now)
        })),
        SESSION_TO_PARENT => unit(linux_keyctl_session_to_parent(now)),
        INVALIDATE => unit(linux_with_keys(|keys, caller| {
            keys.invalidate(caller, id, now)
        })),
        DH_COMPUTE => {
            linux_keyctl_dh_compute(second, third, fourth, fifth, now).unwrap_or_else(|error| error)
        }
        // The argument after the key id is reserved and must be 0.
        PKEY_QUERY if third != 0 => LINUX_EINVAL,
        PKEY_QUERY => unit((|| {
            let info = linux_key_string(fourth, 4096)?;
            let query = linux_with_keys(|keys, caller| keys.pkey_query(caller, id, &info, now))?;
            if !copy_to_linux_user(fifth, &query.to_bytes()) {
                return Err(LINUX_EFAULT);
            }
            Ok(())
        })()),
        RESTRICT_KEYRING => unit((|| {
            let key_type = if third == 0 {
                None
            } else {
                Some(linux_key_type(third)?)
            };
            let restriction = if fourth == 0 {
                None
            } else {
                Some(linux_key_string(fourth, linox_keyrings::DESCRIPTION_LIMIT)?)
            };
            linux_with_keys(|keys, caller| {
                keys.restrict_keyring(caller, id, key_type.as_deref(), restriction.as_deref(), now)
            })
        })()),
        MOVE => unit(linux_with_keys(|keys, caller| {
            keys.move_key(caller, id, third as i32, fourth as i32, fifth as u32, now)
        })),
        CAPABILITIES => crate::linux_keyring::Keyrings::capabilities()
            .map_err(linux_key_error)
            .map_or_else(
                |error| error,
                |output| linux_key_output(&output, second, third),
            ),
        _ => LINUX_EOPNOTSUPP,
    }
}

/// KEYCTL_DH_COMPUTE in Linux's order of checks: the KDF parameters
/// (`struct keyctl_kdf_params`) are copied first; then the parameters must
/// be given and a nonzero length needs a buffer (EINVAL); a KDF must have
/// zeroed spare words (EINVAL), ask for at most 1024 bytes with at most 64
/// of other information (EMSGSIZE) and name a known hash (ENOENT), all
/// before the keys are read. Without a KDF a zero length only asks for the
/// size and a buffer too small for the value is EOVERFLOW. Returns the
/// length written.
fn linux_keyctl_dh_compute(
    parameters: u64,
    buffer: u64,
    length: u64,
    kdf: u64,
    now: u64,
) -> Result<u64, u64> {
    use linox_keyrings::dh;
    const KDF_BYTES: usize = 56;
    let kdf = if kdf == 0 {
        None
    } else {
        let mut raw = [0_u8; KDF_BYTES];
        if !copy_from_linux_user(kdf, &mut raw) {
            return Err(LINUX_EFAULT);
        }
        Some(raw)
    };
    if parameters == 0 || (buffer == 0 && length != 0) {
        return Err(LINUX_EINVAL);
    }
    let mut ids = [0_u8; 12];
    if !copy_from_linux_user(parameters, &mut ids) {
        return Err(LINUX_EFAULT);
    }
    let id = |index: usize| {
        let bytes = ids.as_chunks::<4>().0[index];
        i32::from_ne_bytes(bytes)
    };
    let length = usize::try_from(length).unwrap_or(usize::MAX);
    let derivation = match kdf {
        None => None,
        Some(raw) => {
            let address = |offset: usize| {
                u64::from_ne_bytes(raw[offset..offset + 8].try_into().unwrap_or_default())
            };
            let other_length =
                u32::from_ne_bytes(raw[16..20].try_into().unwrap_or_default()) as usize;
            if raw[20..52].iter().any(|byte| *byte != 0) {
                return Err(LINUX_EINVAL);
            }
            if length > dh::KDF_OUTPUT_LIMIT || other_length > dh::KDF_OTHER_INFO_LIMIT {
                return Err(LINUX_EMSGSIZE);
            }
            let hash = linux_key_string(address(0), dh::HASH_NAME_LIMIT)?;
            dh::check_hash(&hash).map_err(linux_key_error)?;
            Some((hash, address(8), other_length))
        }
    };
    let mut secret =
        linux_with_keys(|keys, caller| keys.dh_compute(caller, id(0), id(1), id(2), now))?;
    let Some((hash, other_address, other_length)) = derivation else {
        if length == 0 {
            return Ok(secret.len() as u64);
        }
        if secret.len() > length {
            return Err(LINUX_EOVERFLOW);
        }
        if !copy_to_linux_user(buffer, &secret) {
            return Err(LINUX_EFAULT);
        }
        return Ok(secret.len() as u64);
    };
    let other = linux_key_payload(other_address, other_length)?;
    secret
        .try_reserve_exact(other.len())
        .map_err(|_| LINUX_ENOMEM)?;
    secret.extend_from_slice(&other);
    let derived = dh::derive(&hash, &secret, length).map_err(linux_key_error)?;
    if !derived.is_empty() && !copy_to_linux_user(buffer, &derived) {
        return Err(LINUX_EFAULT);
    }
    Ok(derived.len() as u64)
}

/// KEYCTL_SESSION_TO_PARENT: the parent takes the caller's session keyring.
/// Like Linux, it refuses (EPERM) a parent that is init, has other threads,
/// or does not run with the caller's effective ids.
fn linux_keyctl_session_to_parent(now: u64) -> Result<(), u64> {
    let pid = current_linux_process_pid();
    let credentials = current_linux_credentials().ok_or(LINUX_ESRCH)?;
    let parent = linux_process::live_process_parent_pid(pid)
        .filter(|parent| *parent > 1)
        .ok_or(LINUX_EPERM)?;
    let parent_credentials = linux_process::live_process_credentials(parent).ok_or(LINUX_EPERM)?;
    let (user, group) = (credentials.user.effective, credentials.group.effective);
    let same_owner = [
        parent_credentials.user.real,
        parent_credentials.user.effective,
        parent_credentials.user.saved,
    ]
    .iter()
    .all(|id| *id == user)
        && [
            parent_credentials.group.real,
            parent_credentials.group.effective,
            parent_credentials.group.saved,
        ]
        .iter()
        .all(|id| *id == group);
    if !same_owner || linux_process_thread_count(parent) > 1 {
        return Err(LINUX_EPERM);
    }
    linux_with_keys(|keys, caller| keys.session_to_parent(caller, parent, now))
}
