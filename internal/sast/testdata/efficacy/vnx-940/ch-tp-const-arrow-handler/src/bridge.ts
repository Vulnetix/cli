type BridgeMessage = { action: string; url: string };

const handleMessage = (event: MessageEvent<BridgeMessage>) => {
  if (event.data.action === 'navigate') {
    window.location.href = event.data.url;
  }
};

~>window.addEventListener('message', handleMessage);
