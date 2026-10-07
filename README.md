# Secure-PWA

Modern PWAs allow easily distributing apps which, after the initial download, work fully offline. This is amazing! No need to compile your app for dozens of architecture and operating system combinations, no need to create one install and update path for each of these combinations.

But for an app to be _useful_, it'll likely need permissions to *do* something. PWAs allow, depending on the browser, access to local files and folders, connected USB devices, Bluetooth, and even access to other devices on the local network.

With a traditional application, you can download the source, check the source (and in the Age of AI, it actually *is* reasonable to audit every single file of every single app you're running) compile it once, then you're sure that it won't change to a malicious version under you.

With PWAs, you have none of these guarantees. The PWA is hosted somewhere, precompiled. It's hard to validate that the  bundle you downloaded in the browser matches to _any_ source revision.

And most PWAs have automatic updates built in, so even if you matched the binaries to source once, you'd have to take extra care to put the browser into offline mode to prevent the PWA from updating itself.

This is where this project comes in. For most people, Github is a trusted authority. Unless you're a Person Of Interest, that's likely to be a reasonable assumption.

Github Actions allows to sign a resulting binary and certify that it was built by Github, based on a specific source revision.

So by utilizing this, and hosting the PWA on Github Pages, it's possible to be, while not completely, but reasonably sure that:

a) the running PWA matches the source code and,

b) if the *self-updater in the PWA, which was verified in the previous step to match the source* verifies the signature of the update, that an update *also* comes from a specific source commit. Updates must be manual, not automatic, to give the user the chance to review the new code.

There are still a few timing based attack vectors, but since the attacker (hopefully) doesn't control the Github Pages web server, they are slim.

An attacker could upload a legitimate PWA bundle, the victim asks their AI agent to download and verify the bundle, which matches. In the meantime, the attacker replaces the bundle with a malicious version. After the Agent gave the green light, the victim opens the site in the browser, downloads and runs the malicious PWA.

This can be solved by not downloading the PWA a second time - open the page in the browser, once, but do not grant it any permissions. Close the browser, validate that *the binaries in the browser cache* match the source code, reopen browser, grant it the required permissions, use the app.

There is one glaring hole in this whole system, updates to the app files can be verified client-side before being aplied, but the service worker itself is updated by the browser, following rules and heuristics set by the browser (like every 24 hours), ignoring cache control headers and without giving the running app a chance to veto the update.

So, this forced service worker update invalidates all the careful update mechanics above - I'd like to use this app as an example I can use to argue for adding new APIs. Of course a running app being able to veto updates to the service worker means in benign cases it might become impossible to update a buggy PWA, requiring the user to manually clear caches or uninstall and reinstall the PWA. But still, I believe this would be extremely valuable.
