# Judge Q&A

Owned by Track P. Keep answers short enough to say in one breath.

| Question | Answer |
|---|---|
| How is this different from Docker? | Containers share the host kernel and don't track which process touched a secret. We enforce in the kernel on exactly the processes that read it. |
| Isn't this just a firewall? | A firewall blocks an IP for everyone. We block only processes that touched the secret. The same IP still works for an untagged process, and we can show that live. |
| Doesn't SELinux/AppArmor do this? | They control access. We control data flow: "you may read this, but afterwards you may only talk to these places." |
| What if it's base64 or encrypted? | Doesn't matter. We never read the content; the process itself is tagged. |
| What if it pipes the data to another program? | Children are covered. Sibling pipelines are a known gap today; pipe/file taint propagation is our next step. |
| Can the program switch it off? | Not without root. The check runs in the kernel, below the program. |
| Performance cost? | Untagged processes pay one hash lookup per connect/send. |
| Who would use it? | Teams running AI agents or untrusted code on their own servers, especially orgs that can't send code to cloud sandboxes. |
