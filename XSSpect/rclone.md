# Rclone + Google Drive Integration Guide

This guide explains how to integrate **rclone** with **Google Drive** to upload and keep your output files (CSV or others) in sync with Drive.

---

## 📌 Prerequisites

* Linux / Ubuntu system
* Google account
* Internet connection

---

## 🔹 Step 1: Install rclone

```bash
sudo apt update
sudo apt install rclone -y
```

Verify installation:

```bash
rclone version
```

---

## 🔹 Step 2: Start rclone configuration

```bash
rclone config
```

Choose:

```text
n) New remote
```

---

## 🔹 Step 3: Name the remote

```text
name> gdrive
```

(`gdrive` is recommended, but you can choose any name.)

---

## 🔹 Step 4: Select Google Drive

From the storage list, choose **Google Drive**:

```text
Storage> 13
```

---

## 🔹 Step 5: Client ID & Client Secret

```text
client_id>
client_secret>
```

➡️ Press **ENTER** for both (default is fine).

---

## 🔹 Step 6: Choose access scope

Select full access:

```text
scope> 1
```

This allows upload, update, and delete operations.

---

## 🔹 Step 7: Root folder & Service Account

```text
root_folder_id>
service_account_file>
```

➡️ Press **ENTER** for both.

---

## 🔹 Step 8: Advanced configuration

```text
Edit advanced config? (y/n)
```

➡️ Type:

```text
n
```

---

## 🔹 Step 9: Browser authentication

```text
Use auto config? (y/n)
```

➡️ Type:

```text
y
```

A browser window will open:

* Login to your Google account
* Allow rclone permissions
* Return to the terminal

---

## 🔹 Step 10: Shared / Team Drive

```text
Configure this as a Shared Drive?
```

➡️ Type:

```text
n
```

---

## 🔹 Step 11: Save the configuration

You will see a summary like:

```text
[gdrive]
type = drive
scope = drive
token = {...}
```

➡️ Confirm:

```text
y
```

Exit config:

```text
q
```

---

## ✅ Step 12: Verify connection

```bash
rclone listremotes
```

Expected output:

```text
gdrive:
```

---

## 🔹 Step 13: Upload files to Google Drive

### Upload a folder

```bash
rclone copy ./outputs gdrive:csv-data
```

### Upload a single file

```bash
rclone copy results.csv gdrive:csv-data
```

A folder named **csv-data** will be created in Google Drive automatically.

---

## 🔹 Step 14: Updating files

### Safe update (recommended)

Uploads new/updated files only, no deletions:

```bash
rclone copy ./outputs gdrive:csv-data
```

### Exact mirror (⚠️ deletes removed files)

```bash
rclone sync ./outputs gdrive:csv-data
```

---

## 🔹 Step 15: Verify uploaded files

```bash
rclone ls gdrive:csv-data
```

---

## 🔹 Step 16: Automate uploads using cron (optional)

Open crontab:

```bash
crontab -e
```

Run upload every 5 minutes:

```bash
*/5 * * * * rclone copy /home/siddharthswami23/Desktop/gdg-hack2skill/xsspect/outputs gdrive:csv-data
```

---

## 🧠 Key Commands Summary

| Command              | Purpose                     |
| -------------------- | --------------------------- |
| `rclone copy`        | Upload new/updated files    |
| `rclone sync`        | Mirror local folder exactly |
| `rclone ls`          | List files in Drive         |
| `rclone listremotes` | Show configured remotes     |

---

## 📂 Config file location

```text
~/.config/rclone/rclone.conf
```

---

## ✅ Done

You now have a working **rclone + Google Drive** integration for automated CSV/file uploads.
