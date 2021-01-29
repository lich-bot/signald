# Debian Installation

put the following in `/etc/apt/sources.list.d/signald.list`:

```
deb https://updates.signald.org unstable main
```

And trust the signing key:

```
curl https://updates.signald.org/apt-signing-key.asc | sudo apt-key add -
```

Update the package list:

```
sudo apt update
```

Now you can install signald:

```
sudo apt install signald
```
