//! `multi` CLI sub-command.

use crate::metadata;
use crate::providers::SudoersPolicy;
use anyhow::{Context, Result};
use clap::{ArgGroup, Parser};

/// Perform multiple tasks in a single call
#[derive(Debug, Parser)]
#[command(group(ArgGroup::new("provider-group").args(["cmdline", "provider"]).required(true)))]
pub struct CliMulti {
    /// The name of the cloud provider
    #[arg(long, value_name = "name")]
    provider: Option<String>,
    /// Read the cloud provider from the kernel cmdline
    #[arg(long)]
    cmdline: bool,
    /// The file into which the metadata attributes are written
    #[arg(long = "attributes", value_name = "path")]
    attributes_file: Option<String>,
    /// Check-in this instance boot with the cloud provider
    #[arg(long)]
    check_in: bool,
    /// The file into which the hostname should be written
    #[arg(long = "hostname", value_name = "path")]
    hostname_file: Option<String>,
    /// The directory into which network units are written
    #[arg(long = "network-units", value_name = "path")]
    network_units_dir: Option<String>,
    /// The directory into which a netplan config is written
    #[arg(long = "netplan-config", value_name = "path")]
    netplan_config_dir: Option<String>,
    /// The directory into which NetworkManager connection profiles are written
    #[arg(long = "networkmanager-profiles", value_name = "path")]
    networkmanager_profiles_dir: Option<String>,
    /// Update SSH keys for the given user
    #[arg(long = "ssh-keys", value_name = "username")]
    ssh_keys_user: Option<String>,
    /// Write a sudoers rule granting the provider admin full sudo access
    #[arg(long = "sudoers", value_name = "path")]
    sudoers_file: Option<String>,
    /// Whether the provider admin must authenticate for sudo
    #[arg(
        long,
        value_enum,
        default_value_t = SudoersPolicy::PasswordRequired,
        requires = "sudoers_file"
    )]
    sudoers_password_policy: SudoersPolicy,
    /// Whether this command was translated from legacy CLI args
    #[arg(long, hide = true)]
    legacy_cli: bool,
}

impl CliMulti {
    /// Run the `multi` sub-command.
    pub(crate) fn run(self) -> Result<()> {
        let provider = super::get_provider(self.provider.as_deref())?;

        if self.attributes_file.is_none()
            && self.network_units_dir.is_none()
            && self.netplan_config_dir.is_none()
            && self.networkmanager_profiles_dir.is_none()
            && !self.check_in
            && self.ssh_keys_user.is_none()
            && self.hostname_file.is_none()
            && self.sudoers_file.is_none()
        {
            slog_scope::warn!("multi: no action specified");
        }

        // fetch the metadata from the configured provider
        let metadata =
            metadata::fetch_metadata(&provider).context("fetching metadata from provider")?;

        // write attributes if configured to do so
        self.attributes_file
            .map_or(Ok(()), |x| metadata.write_attributes(x))
            .context("writing metadata attributes")?;

        // write ssh keys if configured to do so
        self.ssh_keys_user
            .map_or(Ok(()), |x| metadata.write_ssh_keys(x))
            .context("writing ssh keys")?;

        // write hostname if configured to do so
        self.hostname_file
            .map_or(Ok(()), |x| metadata.write_hostname(x))
            .context("writing hostname")?;

        self.sudoers_file
            .map_or(Ok(()), |x| {
                metadata.write_sudoers(x, self.sudoers_password_policy)
            })
            .context("writing sudoers file")?;

        // write network units if configured to do so
        self.network_units_dir
            .map_or(Ok(()), |x| metadata.write_network_units(x))
            .context("writing network units")?;

        // write netplan config if configured to do so
        self.netplan_config_dir
            .map_or(Ok(()), |x| metadata.write_netplan_config(x))
            .context("writing netplan config")?;

        // write NetworkManager profile if configured to do so
        self.networkmanager_profiles_dir
            .map_or(Ok(()), |x| metadata.write_nm_profiles(x))
            .context("writing NetworkManager profile")?;

        // perform boot check-in.
        if self.check_in {
            metadata
                .boot_checkin()
                .context("checking-in instance boot to cloud provider")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sudoers_arguments() {
        let default = CliMulti::try_parse_from([
            "afterburn",
            "--provider",
            "azure",
            "--sudoers",
            "/tmp/afterburn",
        ])
        .unwrap();
        assert_eq!(default.sudoers_file.as_deref(), Some("/tmp/afterburn"));
        assert_eq!(
            default.sudoers_password_policy,
            SudoersPolicy::PasswordRequired
        );

        for (value, expected) in [
            ("required", SudoersPolicy::PasswordRequired),
            ("passwordless", SudoersPolicy::Passwordless),
        ] {
            let config = CliMulti::try_parse_from([
                "afterburn",
                "--provider",
                "azure",
                "--sudoers",
                "/tmp/afterburn",
                "--sudoers-password-policy",
                value,
            ])
            .unwrap();
            assert_eq!(config.sudoers_password_policy, expected);
        }
    }

    #[test]
    fn test_sudoers_policy_requires_path_and_valid_value() {
        assert!(CliMulti::try_parse_from([
            "afterburn",
            "--provider",
            "azure",
            "--sudoers-password-policy",
            "passwordless",
        ])
        .is_err());
        assert!(CliMulti::try_parse_from([
            "afterburn",
            "--provider",
            "azure",
            "--sudoers",
            "/tmp/afterburn",
            "--sudoers-password-policy",
            "invalid",
        ])
        .is_err());
    }
}
