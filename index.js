const express = require("express");
const crypto = require("node:crypto");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

if (!globalThis.crypto) {
  globalThis.crypto = crypto;
}

const PORT = 4001;
const app = express();

app.use(express.static("./public"));
app.use(express.json());

const userStore = {};
const challengeStore = {};

app.post("/register", (req, res) => {
  const { username, password } = req.body;
  const id = `user_${Date.now()}`;

  const user = {
    id,
    username,
    password,
  };
  userStore[id] = user;
  console.log(`Register success`, userStore[id]);
  return res.json({ id });
});

app.post("/register-challenge", async (req, res) => {
  const { userId } = req.body;

  if (!userStore[userId])
    return res.status(404).json({ error: "user not found" });
  const user = userStore[userId];
  const challengePayload = await generateRegistrationOptions({
    rpID: "localhost",
    rpName: "My localhost machine",
    userName: user.username,
  });

  challengeStore[userId] = challengePayload.challenge;

  return res.json({ options: challengePayload });
});

app.post("/register-verify", async (req, res) => {
  const { userId, cred } = req.body;
  const user = userStore[userId];
  const challenge = challengeStore[userId];
  const verificationResult = await verifyRegistrationResponse({
    expectedChallenge: challenge,
    expectedOrigin: "http://localhost:4001",
    expectedRPID: "localhost",
    response: cred,
  });

  if (!verificationResult.verified)
    return res.json({ error: "Could not verify" });
  userStore[userId].passkey = verificationResult.registrationInfo;

  return res.json({ verified: true });
});

app.post("/login-challenge", async (req, res) => {
  const { userId } = req.body;
  const options = await generateAuthenticationOptions({
    rpID: "localhost",
  });
  challengeStore[userId] = options.challenge;

  return res.json({ options });
});

app.post("/login-verify", async (req, res) => {
  const { userId, cred } = req.body;
  const user = userStore[userId];
  const challenge = challengeStore[userId];
  const verificationResult = await verifyAuthenticationResponse({
    expectedChallenge: challenge,
    expectedOrigin: "http://localhost:4001",
    expectedRPID: "localhost",
    response: cred,
    authenticator: user.passkey, // public key jo store kri thi registration k time p
  });

  if (!verificationResult.verified)
    return res.json({ error: "Could not verify" });
  //   userStore[userId].passkey = verificationResult.registrationInfo;
  // user login
  return res.json({ success: true });
});

app.listen(PORT, () =>
  console.log(`Server started at http://localhost:${PORT}`)
);
