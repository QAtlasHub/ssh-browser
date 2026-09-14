//! A certificate authority that can only ever vouch for one suffix.
//!
//! The https mode needs a certificate the browser accepts for `<alias>.<suffix>`, and nobody
//! will issue one: the suffix is not a real TLD and there is no way to prove control of it. So
//! the daemon makes its own authority, and the whole question is how much damage that authority
//! could do if its key leaked.
//!
//! A stock local CA — what `mkcert` installs — could impersonate any site on the internet. The
//! key sits in a file on a laptop, and trusting it means trusting that file more than the web
//! PKI. This one carries `nameConstraints` with a single permitted subtree, the configured
//! suffix, so a leaked key can mint certificates for `*.ssh-browser` and for nothing else.
//! RFC 5280 §4.2.1.10 requires that extension to be marked critical, which is what stops a
//! conforming verifier from quietly ignoring it.
//!
//! Two more limits, for the same reason:
//!
//! - `basicConstraints` carries `pathLenConstraint: 0`, so this authority cannot sign another
//!   authority. Without it a leaked key could mint an intermediate; the name constraint would
//!   still hold, but the blast radius would grow to whatever that intermediate signed.
//! - `keyUsage` is `keyCertSign` and `crlSign` only, so the key cannot serve TLS itself.
//!
//! Every one of those three is read back out of the encoded certificate by `x509-parser`, which
//! is not the code that wrote it. Asserting against `rcgen`'s own view would only say that the
//! builder remembered what it was told; a browser reads bytes, so the tests read bytes.
//!
//! **The daemon never installs this.** Putting a root into a trust store changes how the whole
//! machine treats the internet, is not undone by uninstalling a Rust binary, and is not a
//! decision a background process should make. `ssh-browser trust` prints the command for the
//! platform and stops; running it is the reader's, with the command in front of them.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, GeneralSubtree, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, NameConstraints, SanType, date_time_ymd,
};

/// How long the authority is good for.
///
/// Ten years, because re-trusting a root is a manual step with an alarming dialog in front of
/// it, and making somebody repeat it yearly is how they learn to click through such dialogs
/// without reading them. The serving certificate is short-lived instead, which is where a short
/// lifetime actually buys something.
const AUTHORITY_DAYS: i64 = 3650;

/// How long a serving certificate is good for.
///
/// Reissued from the authority whenever it has expired, which costs no interaction at all — so
/// this can be short without being a nuisance.
const LEAF_DAYS: i64 = 90;

/// The name every authority this module writes is called, and the name the uninstall command
/// looks for. One constant because the two have to agree, and they are in different files.
pub const AUTHORITY_NAME: &str = "ssh-browser local CA";

/// The authority's certificate and the key that signs with it.
pub struct Authority {
    issuer: Issuer<'static, KeyPair>,
    certificate_pem: String,
    suffix: String,
}

impl Authority {
    /// Create an authority permitted to vouch for `suffix` and nothing else.
    pub fn create(suffix: &str) -> Result<Self> {
        // The same rule the PAC and every alias label are held to, asked rather than restated.
        // A suffix that cannot be a hostname produces a constraint no verifier can match, and
        // the failure arrives as a TLS error nowhere near its cause.
        ensure!(
            crate::origin::pac::is_suffix(suffix),
            "suffix {suffix:?} cannot go in a certificate: it must be lowercase letters, digits, hyphens and dots"
        );

        let mut params = CertificateParams::default();

        // Named for what it is and what it is limited to, because this string is what somebody
        // reads in a trust-store list a year from now while deciding whether to remove it.
        // The bare product name would not say which suffix it covers.
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, format!("{AUTHORITY_NAME} ({suffix})"));
        name.push(DnType::OrganizationName, "ssh-browser");
        params.distinguished_name = name;

        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        // The whole point of the module. RFC 5280's DNS rule is that a constraint is satisfied
        // by adding zero or more labels on the left, so `ssh-browser` permits `ssh-browser`
        // itself and `alias.ssh-browser`, and permits nothing else at all.
        //
        // Written without a leading dot deliberately. The dotted form is a convention some
        // implementations accept and the RFC does not describe, and a constraint another
        // verifier reads as "nothing is permitted" would be a certificate that works here and
        // fails on somebody else's machine.
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: vec![GeneralSubtree::DnsName(suffix.to_string())],
            excluded_subtrees: Vec::new(),
        });

        set_validity(&mut params, AUTHORITY_DAYS)?;

        let key = KeyPair::generate().context("generating a key for the local authority")?;
        let certificate_pem = params
            .self_signed(&key)
            .context("signing the local authority")?
            .pem();
        Ok(Self {
            issuer: Issuer::new(params, key),
            certificate_pem,
            suffix: suffix.to_string(),
        })
    }

    /// The authority's certificate, as PEM. The half that is safe to hand out.
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    pub fn suffix(&self) -> &str {
        &self.suffix
    }

    /// A certificate covering every alias under the suffix.
    ///
    /// One certificate rather than one per alias: they are all under the same suffix, a wildcard
    /// covers them, and minting one when an alias is opened would put key generation inside a
    /// TLS handshake.
    ///
    /// `*.suffix` and `suffix` both, because the daemon answers on both — the second is the
    /// index of what is being served.
    pub fn leaf(&self) -> Result<Leaf> {
        self.leaf_named(&[&format!("*.{}", self.suffix), &self.suffix.clone()])
    }

    /// Sign a certificate for whatever names are asked for.
    ///
    /// Takes the names rather than deriving them, so that a test can ask for a name *outside*
    /// the constraint and check that an independent verifier refuses it. That is the only way to
    /// test the claim this module makes: the constraint is enforced by whoever validates the
    /// chain, not by the code that writes it, so a signer that happily produces such a
    /// certificate is expected — being refused downstream is the property.
    fn leaf_named(&self, names: &[&str]) -> Result<Leaf> {
        let first = names
            .first()
            .context("a certificate needs at least one name")?;

        let mut params = CertificateParams::default();
        let mut subject = DistinguishedName::new();
        subject.push(DnType::CommonName, (*first).to_string());
        params.distinguished_name = subject;
        params.subject_alt_names = names
            .iter()
            .map(|name| {
                Ok(SanType::DnsName(
                    (*name)
                        .to_string()
                        .try_into()
                        .with_context(|| format!("{name:?} is not a valid DNS name"))?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        params.use_authority_key_identifier_extension = true;

        set_validity(&mut params, LEAF_DAYS)?;

        let key = KeyPair::generate().context("generating a key for the serving certificate")?;
        let cert = params
            .signed_by(&key, &self.issuer)
            .context("signing the serving certificate")?;
        Ok(Leaf {
            certificate_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        })
    }
}

/// A serving certificate and its key, both as PEM.
pub struct Leaf {
    pub certificate_pem: String,
    pub key_pem: String,
}

/// `not_before` a day ago, `not_after` `days` from now.
///
/// Backdated because a certificate stamped with this instant is not yet valid on a machine whose
/// clock is a minute behind, and that failure arrives as a TLS error with nothing in it to
/// suggest a clock. `date_time_ymd` takes whole days, so a day is the smallest slack available.
/// Assigned into the params rather than returned, so the date type never has to be named here.
/// It belongs to `rcgen`'s own `time` dependency, and taking a direct dependency on that crate
/// to write one signature would be a dependency for a type name.
fn set_validity(params: &mut CertificateParams, days: i64) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("the system clock is before 1970")?
            .as_secs(),
    )
    .context("the system clock is implausibly far in the future")?;
    let today = now / 86_400;

    let (y, m, d) = civil_from_days(today - 1);
    params.not_before = date_time_ymd(y, m, d);
    let (y, m, d) = civil_from_days(today + days);
    params.not_after = date_time_ymd(y, m, d);
    Ok(())
}

/// Howard Hinnant's `civil_from_days`, for days since 1970-01-01.
fn civil_from_days(z: i64) -> (i32, u8, u8) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = u64::try_from(z - era * 146_097).unwrap_or(0);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = i64::try_from(yoe).unwrap_or(0) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u8::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u8::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (
        i32::try_from(if m <= 2 { y + 1 } else { y }).unwrap_or(1970),
        m,
        d,
    )
}

/// What the encoded certificate says about how far it may reach.
///
/// Read with `x509-parser` rather than with `rcgen`, deliberately. The point of checking is that
/// the bytes carry the limits, and asking the library that wrote them would only establish that
/// it remembered its own input.
#[derive(Debug, PartialEq, Eq)]
pub struct Limits {
    /// Permitted DNS subtrees, in the order the certificate lists them.
    pub permitted: Vec<String>,
    /// Excluded DNS subtrees. Expected to be empty: this design permits, it does not exclude.
    pub excluded: Vec<String>,
    /// Whether `nameConstraints` is marked critical, which RFC 5280 requires and which is what
    /// stops a verifier from skipping it.
    pub constraints_critical: bool,
    /// `pathLenConstraint`, if `basicConstraints` gives one. `Some(0)` means it cannot sign
    /// another authority.
    pub path_len: Option<u32>,
    pub is_ca: bool,
    /// Whether `keyUsage` allows anything beyond signing certificates and CRLs.
    pub signs_only_certificates: bool,
}

/// Read the limits out of a PEM certificate.
pub fn limits_of(certificate_pem: &str) -> Result<Limits> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::*;

    let (_, pem) = x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes())
        .context("the certificate is not PEM")?;
    let (_, cert) =
        X509Certificate::from_der(&pem.contents).context("the certificate is not X.509")?;

    let mut limits = Limits {
        permitted: Vec::new(),
        excluded: Vec::new(),
        constraints_critical: false,
        path_len: None,
        is_ca: false,
        signs_only_certificates: false,
    };

    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::NameConstraints(nc) => {
                limits.constraints_critical = ext.critical;
                // Only DNS subtrees are collected. A constraint on some other name form is not
                // something this design writes, and silently counting it as a DNS permission
                // would make a certificate look narrower than it is.
                for tree in nc.permitted_subtrees.iter().flatten() {
                    if let GeneralName::DNSName(name) = tree.base {
                        limits.permitted.push(name.to_string());
                    }
                }
                for tree in nc.excluded_subtrees.iter().flatten() {
                    if let GeneralName::DNSName(name) = tree.base {
                        limits.excluded.push(name.to_string());
                    }
                }
            }
            ParsedExtension::BasicConstraints(bc) => {
                limits.is_ca = bc.ca;
                limits.path_len = bc.path_len_constraint;
            }
            ParsedExtension::KeyUsage(ku) => {
                limits.signs_only_certificates = ku.key_cert_sign()
                    && !ku.digital_signature()
                    && !ku.key_encipherment()
                    && !ku.key_agreement()
                    && !ku.data_encipherment();
            }
            _ => {}
        }
    }
    Ok(limits)
}

/// Is this certificate an authority that can vouch for `suffix` and nothing else?
///
/// Every clause is a separate way the answer could be yes when it should be no, so they are
/// written out rather than folded into one expression: no constraint at all, a constraint on a
/// different suffix, a second permitted subtree beside the right one, an exclusion that changes
/// what the permission means, a constraint a verifier may skip because it is not critical, or an
/// authority that can sign a further authority.
pub fn permits_only(certificate_pem: &str, suffix: &str) -> bool {
    let Ok(limits) = limits_of(certificate_pem) else {
        return false;
    };
    limits.permitted == [suffix]
        && limits.excluded.is_empty()
        && limits.constraints_critical
        && limits.is_ca
        && limits.path_len == Some(0)
        && limits.signs_only_certificates
}

/// Where the authority lives between runs.
///
/// Beside the control token, so it is under the same directory and the same permissions. Not in
/// the configuration directory: a key is state a reader may delete to start again, and
/// configuration is something they wrote and expect to keep.
pub fn authority_dir() -> Option<PathBuf> {
    Some(crate::control::state_dir()?.join("ca"))
}

/// Where the certificate to be trusted goes. Named so `ssh-browser trust` can print it without
/// creating an authority.
pub fn certificate_path() -> Option<PathBuf> {
    Some(authority_dir()?.join("authority.pem"))
}

/// Load the authority for `suffix`, or make one and write it down.
pub fn load_or_create(suffix: &str) -> Result<Authority> {
    let Some(dir) = authority_dir() else {
        bail!("no state directory to keep a local certificate authority in");
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    let key_path = dir.join("authority.key");
    let cert_path = dir.join("authority.pem");

    if let Some(found) = load(&key_path, &cert_path, suffix) {
        return Ok(found);
    }

    let authority = Authority::create(suffix)?;
    // The key through `write_private`, which creates it with the permissions already set. A
    // private key another account can read is the one thing that makes all of the above
    // pointless.
    crate::control::write_private(&key_path, authority.issuer.key().serialize_pem().as_bytes())
        .with_context(|| format!("writing {}", key_path.display()))?;
    std::fs::write(&cert_path, authority.certificate_pem())
        .with_context(|| format!("writing {}", cert_path.display()))?;
    Ok(authority)
}

/// An authority already on disk, if there is one and it is for this suffix.
///
/// Every failure returns `None` and says why, rather than stopping the daemon: a damaged file is
/// a reason to make a new authority, not a reason to serve nothing. It is *said* because the old
/// certificate is in a trust store and the new one is not, so the reader has a step to repeat
/// and no other way to learn that.
fn load(key_path: &Path, cert_path: &Path, suffix: &str) -> Option<Authority> {
    let (Ok(key_pem), Ok(certificate_pem)) = (
        std::fs::read_to_string(key_path),
        std::fs::read_to_string(cert_path),
    ) else {
        return None;
    };

    let key = match KeyPair::from_pem(&key_pem) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("  the stored authority key could not be read ({e}); making a new one");
            return None;
        }
    };

    // Checked before it is used, and checked against the bytes. An authority that is not
    // constrained to this suffix cannot work — a verifier rejects what it signs — and serving
    // from it would produce a TLS error out of a root the reader has already trusted, which is
    // the least debuggable shape available.
    if !permits_only(&certificate_pem, suffix) {
        eprintln!("  the stored authority is not an authority constrained to {suffix:?} alone;");
        eprintln!("  making one that is. The old certificate can be removed from your trust");
        eprintln!("  store: see `ssh-browser trust`.");
        return None;
    }

    match Issuer::from_ca_cert_pem(&certificate_pem, key) {
        Ok(issuer) => Some(Authority {
            issuer,
            certificate_pem,
            suffix: suffix.to_string(),
        }),
        Err(e) => {
            eprintln!("  the stored authority could not be loaded ({e}); making a new one");
            None
        }
    }
}

/// What to run to trust this authority, for the platform this is running on.
///
/// Printed, never executed. The three differ in more than spelling: the Windows one needs no
/// elevation and writes to this account only, the macOS one prompts for a password and writes to
/// the login keychain, and on Linux the location depends on the distribution while Firefox keeps
/// its own store regardless. Guessing wrong while running as somebody's shell is not a thing to
/// do quietly.
pub fn trust_instructions(cert_path: &Path) -> String {
    let path = cert_path.display();
    let preamble = format!(
        "The certificate to trust is\n  {path}\n\n\
         It is an authority constrained to one suffix: if its key leaks, it can vouch for that\n\
         suffix and nothing else. Nothing here installs it — the command below is yours to run,\n\
         and the one after it undoes this.\n\n"
    );
    if cfg!(windows) {
        format!(
            "{preamble}Trust it for this account only, no administrator rights needed:\n\
             \x20 certutil -addstore -user Root \"{path}\"\n\n\
             Undo:\n\
             \x20 certutil -delstore -user Root \"{AUTHORITY_NAME}\"\n\n\
             Check what is there:\n\
             \x20 certutil -store -user Root | findstr /C:\"{AUTHORITY_NAME}\"\n"
        )
    } else if cfg!(target_os = "macos") {
        format!(
            "{preamble}Trust it in your login keychain (it will ask for your password):\n\
             \x20 security add-trusted-cert -k ~/Library/Keychains/login.keychain-db \"{path}\"\n\n\
             Undo:\n\
             \x20 security delete-certificate -c \"{AUTHORITY_NAME}\" ~/Library/Keychains/login.keychain-db\n"
        )
    } else {
        format!(
            "{preamble}Where this goes depends on the distribution. On Debian and Ubuntu:\n\
             \x20 sudo cp \"{path}\" /usr/local/share/ca-certificates/ssh-browser.crt\n\
             \x20 sudo update-ca-certificates\n\n\
             Undo:\n\
             \x20 sudo rm /usr/local/share/ca-certificates/ssh-browser.crt\n\
             \x20 sudo update-ca-certificates --fresh\n\n\
             Firefox keeps its own store and does not read that one. Import it under Settings,\n\
             Privacy & Security, Certificates, View Certificates, Authorities, Import.\n"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every limit, read out of the encoded certificate by a parser that did not write it.
    ///
    /// One test for all of them because they are one claim: this authority reaches exactly as
    /// far as the suffix and no further. Splitting it would let three of the four pass while the
    /// fourth silently regressed.
    #[test]
    fn the_authority_reaches_exactly_its_suffix_and_no_further() {
        let ca = Authority::create("ssh-browser").expect("an authority");
        let limits = limits_of(ca.certificate_pem()).expect("its own output parses");

        assert_eq!(limits.permitted, ["ssh-browser"], "{limits:?}");
        assert!(limits.excluded.is_empty(), "{limits:?}");
        assert!(
            limits.constraints_critical,
            "a name constraint that is not critical may be skipped by a verifier: {limits:?}"
        );
        assert!(limits.is_ca, "{limits:?}");
        assert_eq!(
            limits.path_len,
            Some(0),
            "without pathLen 0 a leaked key can mint an intermediate: {limits:?}"
        );
        assert!(
            limits.signs_only_certificates,
            "the authority key must not be usable to serve TLS: {limits:?}"
        );
    }

    /// And the same certificate does not read as permitting a different suffix.
    ///
    /// The neutering check for the one above: a `permits_only` that ignored its argument would
    /// pass every assertion there.
    #[test]
    fn an_authority_for_one_suffix_does_not_permit_another() {
        let ca = Authority::create("dev").expect("an authority");
        assert!(permits_only(ca.certificate_pem(), "dev"));
        assert!(!permits_only(ca.certificate_pem(), "ssh-browser"));
        assert!(!permits_only(ca.certificate_pem(), "de"));
        assert!(!permits_only(ca.certificate_pem(), ""));
    }

    /// An authority with no constraint at all is refused, not adopted.
    ///
    /// This is the shape a stock local CA has — `mkcert`'s — and the one thing this module
    /// exists to avoid. If such a file appeared in the state directory, by hand or from a
    /// `mkcert` run pointed there, adopting it would mean serving from a root that can
    /// impersonate anything.
    #[test]
    fn an_unconstrained_authority_is_not_adopted() {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().expect("a key");
        let pem = params.self_signed(&key).expect("self signed").pem();

        let limits = limits_of(&pem).expect("parses");
        assert!(limits.permitted.is_empty(), "{limits:?}");
        assert_eq!(limits.path_len, None, "{limits:?}");
        assert!(
            !permits_only(&pem, "ssh-browser"),
            "an unconstrained authority must never be treated as constrained"
        );
    }

    /// An authority that permits a second subtree is refused too.
    ///
    /// Narrower than the case above and more likely: somebody edits the file, or an older
    /// version of this wrote two. Permitting `ssh-browser` *and* something else is not the
    /// promise the trust decision was made against.
    #[test]
    fn a_second_permitted_subtree_is_refused() {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: vec![
                GeneralSubtree::DnsName("ssh-browser".to_string()),
                GeneralSubtree::DnsName("example.com".to_string()),
            ],
            excluded_subtrees: Vec::new(),
        });
        let key = KeyPair::generate().expect("a key");
        let pem = params.self_signed(&key).expect("self signed").pem();

        assert_eq!(
            limits_of(&pem).expect("parses").permitted,
            ["ssh-browser", "example.com"]
        );
        assert!(!permits_only(&pem, "ssh-browser"));
    }

    /// A suffix that cannot be a hostname cannot go in a certificate either.
    #[test]
    fn a_suffix_that_is_not_a_hostname_is_refused() {
        for bad in ["Has Caps", "with space", "with/slash", "", "under_score"] {
            assert!(
                Authority::create(bad).is_err(),
                "{bad:?} should not have produced an authority"
            );
        }
    }

    /// The serving certificate covers every alias and the bare suffix, and is not an authority.
    #[test]
    fn the_leaf_covers_the_wildcard_and_is_not_itself_an_authority() {
        use x509_parser::prelude::*;

        let ca = Authority::create("ssh-browser").expect("an authority");
        let leaf = ca.leaf().expect("a leaf");
        assert!(leaf.key_pem.contains("PRIVATE KEY"));

        let (_, pem) = x509_parser::pem::parse_x509_pem(leaf.certificate_pem.as_bytes())
            .expect("the leaf is PEM");
        let (_, cert) = X509Certificate::from_der(&pem.contents).expect("the leaf is X.509");
        let names: Vec<String> = cert
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|san| {
                san.value
                    .general_names
                    .iter()
                    .filter_map(|n| match n {
                        x509_parser::extensions::GeneralName::DNSName(d) => Some(d.to_string()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        assert!(names.contains(&"*.ssh-browser".to_string()), "{names:?}");
        assert!(names.contains(&"ssh-browser".to_string()), "{names:?}");

        // A serving certificate that was also an authority would be able to sign for the whole
        // suffix, and it is handed to whatever terminates TLS.
        assert!(
            !limits_of(&leaf.certificate_pem).expect("parses").is_ca,
            "the serving certificate must not be a CA"
        );
    }

    /// Instructions name the file and say how to undo the install.
    #[test]
    fn the_instructions_name_the_certificate_and_how_to_undo_it() {
        let said = trust_instructions(Path::new("/tmp/authority.pem"));
        assert!(said.contains("authority.pem"), "{said}");
        assert!(
            said.contains("Undo:"),
            "telling somebody to install a root without saying how to remove it is half an \
             instruction: {said}"
        );
        assert!(said.contains(AUTHORITY_NAME), "{said}");
    }

    /// An independent verifier refuses a name outside the constraint.
    ///
    /// This is the only test here that checks the *claim* rather than the encoding. Everything
    /// above establishes that the certificate says what it should; a name constraint is enforced
    /// by whoever validates the chain, so a signer that happily mints `evil.example` is expected
    /// and being refused downstream is the whole property.
    ///
    /// `openssl verify` is the verifier because it is a third implementation — not `rcgen` which
    /// wrote the bytes, and not `x509-parser` which read them back. It is on all three CI
    /// runners. When it is absent the test says so rather than passing quietly, because a check
    /// that silently does nothing is worse than one that is missing.
    #[test]
    fn an_independent_verifier_refuses_a_name_outside_the_constraint() {
        use std::process::Command;

        let Ok(version) = Command::new("openssl").arg("version").output() else {
            println!(
                "  SKIPPED an_independent_verifier_refuses_a_name_outside_the_constraint: \
                 no openssl on PATH"
            );
            return;
        };
        assert!(
            version.status.success(),
            "openssl is on PATH but would not run"
        );

        let ca = Authority::create("ssh-browser").expect("an authority");
        let inside = ca
            .leaf_named(&["alias.ssh-browser"])
            .expect("a name inside the constraint");
        let outside = ca
            .leaf_named(&["evil.example"])
            .expect("the signer does not police this; the verifier does");

        let dir = std::env::temp_dir().join(format!("ssh-browser-nc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temporary directory");
        let ca_path = dir.join("ca.pem");
        let inside_path = dir.join("inside.pem");
        let outside_path = dir.join("outside.pem");
        std::fs::write(&ca_path, ca.certificate_pem()).expect("write the authority");
        std::fs::write(&inside_path, &inside.certificate_pem).expect("write the good leaf");
        std::fs::write(&outside_path, &outside.certificate_pem).expect("write the bad leaf");

        let verify = |leaf: &Path| {
            let out = Command::new("openssl")
                .arg("verify")
                .arg("-CAfile")
                .arg(&ca_path)
                .arg(leaf)
                .output()
                .expect("openssl verify runs");
            let said = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            (out.status.success(), said)
        };

        let (ok, said) = verify(&inside_path);
        assert!(ok, "a name under the suffix should verify: {said}");

        let (ok, said) = verify(&outside_path);
        assert!(
            !ok,
            "openssl accepted a certificate for evil.example from an authority constrained to \
             ssh-browser, which means the constraint is buying nothing: {said}"
        );
        // The reason, not just the refusal. A leaf rejected for an expired date or a bad
        // signature would fail the assertion above while saying nothing about name constraints.
        assert!(
            said.to_lowercase().contains("subtree")
                || said.to_lowercase().contains("name constraint")
                || said.to_lowercase().contains("excluded"),
            "refused, but not for the constraint -- so this test is not measuring it: {said}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The date arithmetic, against a calendar rather than against itself.
    #[test]
    fn days_since_the_epoch_become_the_right_date() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(1), (1970, 1, 2));
        // 2000-03-01, just past a leap day in a year divisible by 400.
        assert_eq!(civil_from_days(11017), (2000, 3, 1));
        assert_eq!(civil_from_days(11016), (2000, 2, 29));
    }

    /// The certificate is valid now, and for about as long as it says.
    ///
    /// Backdating is the part worth pinning: without it a machine whose clock is a minute behind
    /// gets a TLS error with nothing in it about clocks.
    #[test]
    fn the_authority_is_already_valid_and_the_leaf_expires_sooner() {
        use x509_parser::prelude::*;

        let read = |pem: &str| {
            let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("PEM");
            let (_, c) = X509Certificate::from_der(&p.contents).expect("X.509");
            (
                c.validity().not_before.timestamp(),
                c.validity().not_after.timestamp(),
            )
        };
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("after 1970")
                .as_secs(),
        )
        .expect("a plausible clock");

        let ca = Authority::create("ssh-browser").expect("an authority");
        let (ca_from, ca_until) = read(ca.certificate_pem());
        assert!(
            ca_from < now,
            "the authority is not valid yet: {ca_from} > {now}"
        );
        assert!(ca_until > now, "the authority has already expired");

        let (leaf_from, leaf_until) = read(&ca.leaf().expect("a leaf").certificate_pem);
        assert!(leaf_from < now, "the leaf is not valid yet");
        assert!(
            leaf_until < ca_until,
            "the leaf must not outlive the authority that signed it"
        );
    }
}
