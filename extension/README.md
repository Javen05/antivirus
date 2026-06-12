# ClearGuard Web Shield

This unpacked Chrome/Edge extension asks the local ClearGuard agent to inspect visited URLs. It shows a browser warning badge/notification and redirects high-risk pages to a local ClearGuard warning screen with a one-time "continue anyway" option.

## Install For Testing

1. Start ClearGuard locally:

   ```powershell
   python server.py
   ```

2. Open Chrome or Edge extension settings.
3. Enable Developer mode.
4. Choose **Load unpacked**.
5. Select this `extension` folder.

The extension needs the local agent at `http://127.0.0.1:5288/`. It does not upload browsing history to a cloud service.
