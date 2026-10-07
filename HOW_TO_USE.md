# How to Run OFT

## What you need installed first

- **Node.js** (version 18 or newer) — download it from [nodejs.org](https://nodejs.org). Grab the **LTS** version and run the installer with default settings. This also installs **npm** automatically, which you'll need.
- **An internet connection** — the setup step downloads Electron (~100–150 MB), so make sure you're online for that part.
- Nothing else. No Python, no Git, no Visual Studio — just Node.js.

## Files you need in the folder

Before starting, make sure you have all of these files:

- `main.js`
- `preload.js`
- `index.html`
- `package.json`

If you also have `package-lock.json`, keep that too — it's not required, but it helps npm install the exact same versions every time.

Don't have `node_modules` or an `out` folder — you don't need them and they'll be created automatically.

## Step-by-step

**1. Create a folder anywhere on your PC**

This can be anywhere — your Desktop, Documents, wherever. For example:

```
C:\Users\<your-username>\Documents\my-app
```

Name the folder whatever you want (it doesn't have to be `my-app`).

**2. Put all the files in that folder**

Copy `main.js`, `preload.js`, `index.html`, and `package.json` directly into the folder you just made — not inside a subfolder, they need to sit right in that folder together.

**3. Open Command Prompt**

Press the **Windows key**, type `cmd`, and press Enter.

**4. Navigate to your folder**

Type `cd` followed by a space, then the path to your folder, and press Enter. For example:

```
cd C:\Users\USER's NAME\Documents\my-app
```

Tip: you can also type `cd ` (with the space) in Command Prompt, then drag the folder from File Explorer into the window — it'll paste the correct path for you automatically.

**5. Install dependencies**

Still in that Command Prompt window, run:

```
npm install
```

This downloads Electron and everything else the app needs. It can take a minute or two — let it finish.

**6. Run the app**

```
npm start
```

A window should open and the app will launch.

## Running it again later

You only need to do steps 3, 4, and 6 next time — `npm install` (step 5) only needs to be run once, unless you delete the `node_modules` folder or get new files that change `package.json`.

## If something goes wrong

- **`'node' is not recognized`** — Node.js isn't installed, or you need to close and reopen Command Prompt after installing it.
- **`'npm' is not recognized`** — same fix as above; npm comes with Node.js.
- **`npm install` fails** — check your internet connection and try again.
- **The window opens but looks broken or blank** — make sure all four files are actually in the same folder, with no typos in the filenames.