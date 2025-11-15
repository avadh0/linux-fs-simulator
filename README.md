# Linux File System Simulator (C)

## 📌 Project Overview

* A simple **in-memory Linux/UNIX-style file system simulator** written in C.
* Demonstrates understanding of **Operating Systems, File Systems, Inodes, and Block Management**.
* Supports basic file system operations like **create, delete, write, read, list, and stat**.
* Includes a built-in **command-line shell** to interact with the simulated FS.

---

## 🚀 Features

* In-memory inode table
* Block allocation & free system
* Directory structure with entries (like UNIX V6)
* Direct blocks for file storage
* Basic file and directory operations:

  * `mkdir`
  * `touch`
  * `rm`
  * `write`
  * `cat`
  * `ls`
  * `stat`
  * `format`
* Simple REPL for interacting with FS
* Fully self-contained single C file (`simplefs.c`)

---

## 🧠 Concepts Demonstrated

* OS-level file system logic
* Inodes and metadata
* Data block mapping
* Directory hierarchy
* Path parsing
* Dynamic memory management
* Basic shell command handling

---

## 📂 File Structure

```
linux-fs-simulator/
│── simplefs.c     # Main project source code
│── README.md      # Project documentation
```

---

## 🛠️ How to Compile

Use GCC:

```
gcc simplefs.c -o simplefs -std=c99 -Wall -Wextra
```

---

## ▶️ How to Run

Start with interactive shell:

```
./simplefs
```

Or run the demo mode:

```
./simplefs --demo
```

---

## 📝 Example Commands (inside program)

```
fs$ mkdir /docs
fs$ write /docs/note This is a test file
fs$ ls /docs
fs$ cat /docs/note
fs$ stat /docs/note
fs$ rm /docs/note
```

---

## ⚙️ Limitations

* Max 128 inodes
* Max 2048 blocks
* No indirect blocks (files up to ~5 KB)
* No permissions or timestamps
* Not persistent (resets on exit)

---

## 📚 Future Improvements

* Add indirect blocks to support larger files
* Add persistent disk storage (save/load FS)
* Implement permissions & timestamps
* Add relative paths & `cd` command
* Add file descriptors and true `open/read/write`

---

## 👤 Author

Project uploaded by **avadh0** on GitHub.

