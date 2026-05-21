// Minimal UI behaviour for openTIcollect. No framework; delegated listeners only.
(function () {
  // A click on a finding's checkbox must not also open the detail panel.
  // Capture phase runs before the row's htmx click handler.
  document.addEventListener("click", function (e) {
    var t = e.target;
    if (t && t.tagName === "INPUT" && t.type === "checkbox" &&
        (t.classList.contains("finding-check") || t.id === "select-all")) {
      e.stopPropagation();
    }
  }, true);

  // The select-all checkbox toggles every row checkbox.
  document.addEventListener("change", function (e) {
    if (e.target && e.target.id === "select-all") {
      var boxes = document.querySelectorAll(".finding-check");
      for (var i = 0; i < boxes.length; i++) {
        boxes[i].checked = e.target.checked;
      }
    }
  });
})();
