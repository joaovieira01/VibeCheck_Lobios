import { exec } from "node:child_process";

export function resize(req) {
  exec(`resize-image ${req.body.filename} --width 640`);
}
