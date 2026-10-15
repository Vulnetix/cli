// Never do this: sessionId++ or token = String(++counter)
/* resetToken = lastToken + 1 is guessable */
console.log("token = counter++ would be predictable");
const help = 'session_id = next(ids)';
