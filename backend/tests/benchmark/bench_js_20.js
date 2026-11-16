export function setCookie(res, token) {
  res.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });
}
