# Aruba QuickConnect 4 All
Aruba QuickConnect for All (aqc4all) is a Linux-first tool to help users enrol in Aruba-managed wireless networks without needing to run Ubuntu or submit to opaque and insecure vendor tools.

Many universities and workplaces are migrating to Aruba-managed wireless networks and shutting down self-managed ones. The official Aruba QuickConnect client is available only for Windows, macOS, Android, iOS, and Ubuntu 22.04 (and only if you're running systemd and NetworkManager, which cuts out quite a few Ubuntu-based distributions).

What this means is that if you're running Debian, Arch, Fedora, Gentoo, Slackware, BSD, or even Linux Mint, you can't really get your Linux machine enrolled without getting extremely "hacky". 

Aruba's onboarding portal straight-up refuses to offer you the download link, unless you have "Ubuntu" in your User-Agent.

, IT departments are usually unable (or unwilling) to help Linux users connect.

So we built this.


`aqc4all` automates and simplifies the Aruba QuickConnect enrollment process for all Linux systems. Here's what it does differently (and better):
- Spoofs the User-Agent to trick the Aruba portal into handing over the precious installer
- Extracts only the relevant part (read: a one-time pad (OTP) from a config.ini file) from their bloated 43MB installer
- Generates secure, modern keypairs (unlike the official tool, which requires downgrading OpenSSL)
- Sends the public key to Aruba’s EST server, retrieves a signed certificate and the CA
- Optionally installs configuration files for:
    - `NetworkManager`
    - `wpa_supplicant`
    - `iwd`
    - `systemd-networkd`
    - `connman`
    - `wicked`
    - `netctl`
    - `netifrc`

It will also generate Android configs for you that aren't locked up with someone else's key, so you can change them!

Currently, it only supports Firefox and Chromium.  Chromium-based browsers should also work, however that has not been tested yet.  

Same for BSD support.  There's no reason it shouldn't work, we just haven't tested it yet.

## Why use this and not the official tool?
- Works on any Linux distribution (and likely BSD)
- Works with almost any networking components
   - And saves the raw files, so you can manually configure it later, if you choose
- Generates key lengths that are actually considered "safe" (minimum 4096-bit)
- Much more transaparent than the official tool

## Installation
```
git clone https://github.com/alzer89/ArubaQuickConnect4All
cd ArubaQuickConnect4All
pip install .
```

## Browser Requirements
`geckodriver` (for Firefox) and/or `chromedriver` (for Chromium) is currently required to allow ArubaQuickConnect4All to control a Firefox window, and `aqc4all` will prompt you if you wish to install this as part of the process.  You can, of course, install it yourself manually if you wish.  Be warned that very few distros will keep copies of `geckodriver` in their (stable) repos.

## PyPi Package
Work is being done to submit this to PyPi as a standalone package.

## Usage
Literally just run `aqc4all`, and it'll guide you through the steps. 

For advanced options:
```
aqc4all --help
```


## Backstory - and slight rant
Aruba QuickConnect is very well-supported on Windows, macOS, iOS and Android, but there's almost nothing for Linux.  The most that exists is Ubuntu 22.04 LTS, and you must have systemd and networkmanager installed for their proprietary tool to function.  Naturally, this causes quite a few linux and BSD users to be left with little to no support.  

Moreover, many universities and workplaces are moving to wireless networks managed by Aruba QuickConnect, and shutting down their own self-managed networks, in favour of outsourcing.  The issue with this is that the overwhelming majority of Linux users have almost no way of connecting to these networks, and IT departments are generally absolutely useless when it comes to this.  

The prescribed way of enrolling with Aruba QuickConnect is first visiting a website usually run by the network provider.  This website seems to look for "Ubuntu" in the browser's User-Agent.  Whilst almost all Linux distros will declare "Linux" in their User-Agent, if "Ubuntu" is not part of it, the website will refuse to offer a download of the installer tool.  Because of this, Debian, Fedora, Arch, Gentoo, Slackware, and even Linux Mint users will never be able to enrol onto one of these networks without "getting hacky".  

So, aqc4all will spoof the User-Agent, allowing the website to offer a download of the "installer tool", which is the fanciest way of saying "a 43MB bash script with a gzip tarball tacked on the end from line 505" (-_-').  

Why is it so big, you ask?  I have no idea.  It seems to include quite a lot of shared libraries in that tarball, many of which don't seem necessary at all (like libcupsd.so, WHY IS THAT NEEDED FOR WIFI!?!?!?!).

The only part you really need from all this garbage is a single line in a file called config.ini, and that contains a one-time-pad (otp).  This is literally the only thing you need to give the server, and it will allow you to generate a config.  

The official tool will then generate grossly insecure keypairs (I actually had to downgrade my version of OpenSSL to be able to generate them!), upload the public one to the server, to receive a certificate back.  It will also reply with the server's root certificate.  

The official tool will then obfuscate and hide the keys, certificates "somewhere in your filesystem"

So, this tool has been made to do all of these ridiculous steps in a way that is more transparent, more versatile, and more secure than the official tool.  

This tool will generate much MUCH longer key lengths, which the server seems to have absolutely no problem accepting.  

This tool is also filled with arguments you can add to customise what you can do with it.  

I hope you find it useful, and if you feel like contributing, please feel free to.  
