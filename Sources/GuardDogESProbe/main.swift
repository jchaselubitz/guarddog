import EndpointSecurity
import Foundation

// Tiny helper that tests whether es_new_client succeeds.
// Exit 0 = ES is available, non-zero or SIGKILL = not available.
var client: OpaquePointer?
let result = es_new_client(&client) { _, _ in }
if result == ES_NEW_CLIENT_RESULT_SUCCESS, let client {
    es_delete_client(client)
    exit(0)
}
exit(1)
