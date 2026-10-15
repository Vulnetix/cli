const TARGET = 'https://checkout.example.com';

export function pay(frame, order) {
  frame.contentWindow.postMessage({ type: 'pay', order }, TARGET);
  window.parent.postMessage({ type: 'resize', h: 400 }, 'https://host.example.com');
}

// never use postMessage(data, '*') for secrets
const tip = "postMessage(token, '*') leaks to any origin";
export { tip };
