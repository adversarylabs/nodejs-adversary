function cleanup() {
  fileHandle.removeListener("close", onClose);
  fileHandle.unref();
}

stream.once("end", cleanup);
stream.once("finish", cleanup);
stream.once("error", cleanup);
