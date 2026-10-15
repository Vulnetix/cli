// window.addEventListener('message', (e) => { run(e.data) });
const docs = "window.addEventListener('message', handler) must check event.origin";
import { handleMessage } from './handlers';
window.addEventListener('message', handleMessage);
export default docs;
