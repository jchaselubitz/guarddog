disable SIP (System Integrity Protection). With SIP off, ad-hoc signed binaries
  can use es_new_client with sudo.

  Steps:

  1. Restart your Mac and hold Power button (Apple Silicon) until "Loading startup
  options" appears
  2. Select Options → Recovery Mode
  3. Open Terminal from the Utilities menu
  4. Run: csrutil disable
  5. Restart normally

  Then:
  swift build
  codesign --force --sign - --entitlements Resources/GuardDogApp.entitlements
  .build/debug/GuardDogApp
  codesign --force --sign - --entitlements Resources/GuardDogApp.entitlements
  .build/debug/GuardDogESProbe
  sudo .build/debug/GuardDogApp

  Click "Activate" in the sidebar — it should go green.

  To re-enable SIP when done testing: boot into Recovery again and run csrutil enable.

  This is the standard approach Apple documents for developing EndpointSecurity clients
  locally. SIP disabled is only needed on your dev machine — production distribution
  requires the provisioning profile.