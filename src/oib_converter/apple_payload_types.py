"""Apple's configuration-profile payload types, in their canonical casing.

macOS matches PayloadType case-sensitively. A payload whose type mis-cases one
of Apple's types is not treated as that payload: on macOS 27.0.1 (2026-10-15)
a `com.apple.tcc.configuration-profile-policy` payload was installed as a
plain custom-preferences domain
(/Library/Managed Preferences/com.apple.tcc.configuration-profile-policy.plist),
so TCC never saw its grants. Apple's type is
`com.apple.TCC.configuration-profile-policy`.

The Graph settings-catalogue IDs the converter derives Apple payload types
from are all lowercase (`com.apple.tcc.configuration-profile-policy_services`),
so the converter must restore Apple's casing. It looks the type up here
instead of keeping a hand-written map that has to anticipate every
mixed-case type.
"""

from __future__ import annotations

# Every distinct com.apple.* `payloadtype` in apple/device-management
# mdm/profiles/*.yaml at Release-v27.0 (commit
# 09f249a06e7e3289930bf6d05f38fb562f748ebf), canonical casing: 117 types. The
# 127 YAML files hold 121 distinct values (com.apple.MCX appears in 6 files,
# com.apple.extensiblesso in 2); the 4 that are not com.apple.* are left out
# (.GlobalPreferences, loginwindow, and the CommonPayloadKeys and TopLevel
# schema pseudo-types). The same list backs Talieisin/macos-intune's
# tools/check-mobileconfig-payloads.py guard; keep the two in step. Refresh
# from a newer release when Apple adds payload types. A type missing here is
# passed through unchanged.
APPLE_PAYLOAD_TYPES = frozenset(
    {
        "com.apple.ADCertificate.managed",
        "com.apple.AIM.account",
        "com.apple.airplay",
        "com.apple.airplay.security",
        "com.apple.airprint",
        "com.apple.apn.managed",
        "com.apple.app.lock",
        "com.apple.applicationaccess",
        "com.apple.applicationaccess.new",
        "com.apple.appstore",
        "com.apple.asam",
        "com.apple.AssetCache.managed",
        "com.apple.associated-domains",
        "com.apple.caldav.account",
        "com.apple.carddav.account",
        "com.apple.cellular",
        "com.apple.cellularprivatenetwork.managed",
        "com.apple.conferenceroomdisplay",
        "com.apple.configurationprofile.identification",
        "com.apple.dashboard",
        "com.apple.declarations",
        "com.apple.desktop",
        "com.apple.Dictionary",
        "com.apple.DirectoryService.managed",
        "com.apple.DiscRecording",
        "com.apple.dnsProxy.managed",
        "com.apple.dnsSettings.managed",
        "com.apple.dock",
        "com.apple.domains",
        "com.apple.eas.account",
        "com.apple.education",
        "com.apple.ews.account",
        "com.apple.extensiblesso",
        "com.apple.familycontrols.contentfilter",
        "com.apple.familycontrols.timelimits.v2",
        "com.apple.fileproviderd",
        "com.apple.finder",
        "com.apple.firstactiveethernet.managed",
        "com.apple.firstethernet.managed",
        "com.apple.font",
        "com.apple.gamed",
        "com.apple.globalethernet.managed",
        "com.apple.google-oauth",
        "com.apple.homescreenlayout",
        "com.apple.ironwood.support",
        "com.apple.jabber.account",
        "com.apple.ldap.account",
        "com.apple.loginitems.managed",
        "com.apple.loginwindow",
        "com.apple.lom",
        "com.apple.mail.managed",
        "com.apple.ManagedClient.preferences",
        "com.apple.MCX",
        "com.apple.MCX.FileVault2",
        "com.apple.MCX.TimeMachine",
        "com.apple.mcxloginscripts",
        "com.apple.mcxMenuExtras",
        "com.apple.mcxprinting",
        "com.apple.mdm",
        "com.apple.mobiledevice.passwordpolicy",
        "com.apple.networkusagerules",
        "com.apple.notificationsettings",
        "com.apple.NSExtension",
        "com.apple.osxserver.account",
        "com.apple.preference.security",
        "com.apple.preference.users",
        "com.apple.profileRemovalPassword",
        "com.apple.proxy.http.global",
        "com.apple.relay.managed",
        "com.apple.screensaver",
        "com.apple.screensaver.user",
        "com.apple.secondactiveethernet.managed",
        "com.apple.secondethernet.managed",
        "com.apple.security.acme",
        "com.apple.security.certificatepreference",
        "com.apple.security.certificaterevocation",
        "com.apple.security.certificatetransparency",
        "com.apple.security.FDERecoveryKeyEscrow",
        "com.apple.security.FDERecoveryRedirect",
        "com.apple.security.firewall",
        "com.apple.security.identitypreference",
        "com.apple.security.pem",
        "com.apple.security.pkcs1",
        "com.apple.security.pkcs12",
        "com.apple.security.root",
        "com.apple.security.scep",
        "com.apple.security.smartcard",
        "com.apple.servicemanagement",
        "com.apple.SetupAssistant.managed",
        "com.apple.shareddeviceconfiguration",
        "com.apple.ShareKitHelper",
        "com.apple.SoftwareUpdate",
        "com.apple.sso",
        "com.apple.subscribedcalendar.account",
        "com.apple.syspolicy.kernel-extension-policy",
        "com.apple.system-extension-policy",
        "com.apple.system.logging",
        "com.apple.SystemConfiguration",
        "com.apple.systemmigration",
        "com.apple.systempolicy.control",
        "com.apple.systempolicy.managed",
        "com.apple.systempolicy.rule",
        "com.apple.systempreferences",
        "com.apple.systemuiserver",
        "com.apple.TCC.configuration-profile-policy",
        "com.apple.thirdactiveethernet.managed",
        "com.apple.thirdethernet.managed",
        "com.apple.tvremote",
        "com.apple.universalaccess",
        "com.apple.vpn.managed",
        "com.apple.vpn.managed.applayer",
        "com.apple.vpn.managed.appmapping",
        "com.apple.webClip.managed",
        "com.apple.webcontent-filter",
        "com.apple.wifi.managed",
        "com.apple.xsan",
        "com.apple.xsan.preferences",
    }
)

_CANONICAL_BY_LOWER = {t.lower(): t for t in APPLE_PAYLOAD_TYPES}


def canonical_apple_payload_type(payload_type: str) -> str:
    """Return Apple's spelling of `payload_type`, or `payload_type` unchanged.

    Matching is case-insensitive. A type not in APPLE_PAYLOAD_TYPES (a vendor
    domain, or a custom com.apple.* preference domain such as
    com.apple.TimeMachine) is returned as given.
    """
    return _CANONICAL_BY_LOWER.get(payload_type.lower(), payload_type)
