function cleanup() {
  stream.removeListener("end", cleanup);
  stream.removeListener("finish", cleanup);
  stream.removeListener("error", cleanup);
  fileHandle.removeListener("close", onClose);
  fileHandle.unref();
}

stream.once("end", cleanup);
stream.once("finish", cleanup);
stream.once("error", cleanup);

const onData = (chunk) => consume(chunk);
stream.on("data", onData);

function settle() {
  clearTimeout(timer);
}

request.once("error", settle);
response.once("close", settle);

function observeLifecycle() {
  lifecycleEvents += 1;
}

worker.on("error", observeLifecycle);
worker.on("exit", observeLifecycle);
