# TODOs

* In signatures hash id instead of just "email"
* Fix the promise hell in loi_server and other places and all other anti-patterns...
* Currently the Nintendo provider computes the access token in the server module. This is not safe and was done only for simplicity to carry out testing quickly. Fix it.
* Add some joint provider as explained in the README
* Better error handling, parsing of emails, phone numbers, compatibility of options
* revocation via OCSP for DIC
* Example of token with real social features? (e.g., token for Instagram users with a certain number of followers, or FB token for friends of a given user...)
