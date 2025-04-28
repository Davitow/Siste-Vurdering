function checkAnswers() {
    var score = 0;
    var totalQuestions = 3;

    // Check question 1
    if (document.getElementById('q1b').checked) score++;

    // Check question 2
    if (document.getElementById('q2a').checked) score++;

    // Check question 3
    if (document.getElementById('q3c').checked) score++;

    // Show result
    var result = document.getElementById('result');
    result.innerHTML = "You scored " + score + " out of " + totalQuestions;
  }