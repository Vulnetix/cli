function nextQuestion(req, res) {
  const q = pick(Math.floor(Math.random() * questions.length));
  const quiz = { question: q.text, answer: q.answer };
  res.json(quiz);
}
module.exports = { nextQuestion };
