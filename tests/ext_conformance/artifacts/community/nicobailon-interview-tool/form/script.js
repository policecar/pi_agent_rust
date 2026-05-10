(function () {
  const data = window.__PI_INTERVIEW_DATA__ || {};
  const root = document.getElementById("app");
  if (!root) {
    return;
  }

  const title = document.createElement("h1");
  title.textContent = data.title || "Interview";

  const shell = document.createElement("section");
  shell.className = "interview-shell";
  shell.appendChild(title);

  for (const question of data.questions || []) {
    const item = document.createElement("article");
    item.className = "question";

    const heading = document.createElement("h2");
    heading.textContent = question.question || question.id || "Question";
    item.appendChild(heading);

    if (question.context) {
      const context = document.createElement("p");
      context.textContent = question.context;
      item.appendChild(context);
    }

    shell.appendChild(item);
  }

  root.appendChild(shell);
})();
