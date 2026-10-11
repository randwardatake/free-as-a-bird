// Small progressive enhancements. Every page works without this file.
(function () {
  "use strict";
  var replyBox = document.querySelector('.postform input[name="thread"]') && document.getElementById("f-body");

  document.addEventListener("click", function (e) {
    // Click "No.xxxx" on a thread page to quote that post in the reply box.
    var num = e.target.closest(".postnum");
    if (num && replyBox) {
      e.preventDefault();
      var q = ">>" + num.dataset.quote + "\n";
      var at = replyBox.selectionStart || replyBox.value.length;
      replyBox.value = replyBox.value.slice(0, at) + q + replyBox.value.slice(at);
      replyBox.focus();
      replyBox.selectionStart = replyBox.selectionEnd = at + q.length;
      return;
    }
    // Click a thumbnail to expand it in place; click again to shrink.
    var thumb = e.target.closest("a.thumb");
    if (thumb && !e.ctrlKey && !e.metaKey && e.button === 0) {
      e.preventDefault();
      var img = thumb.querySelector("img");
      if (!thumb.dataset.thumb) thumb.dataset.thumb = img.getAttribute("src");
      var expand = !thumb.classList.contains("expanded");
      thumb.classList.toggle("expanded", expand);
      img.src = expand ? thumb.getAttribute("href") : thumb.dataset.thumb;
    }
  });

  // Hover a >>quote to preview the post if it is on this page.
  var preview = null;
  document.addEventListener("mouseover", function (e) {
    var link = e.target.closest(".quotelink");
    if (!link) return;
    var target = document.querySelector('.post[data-id^="' + link.dataset.id.slice(0, 10) + '"]');
    if (!target) return;
    preview = target.cloneNode(true);
    preview.id = "preview";
    preview.classList.add("reply");
    document.body.appendChild(preview);
    var r = link.getBoundingClientRect();
    preview.style.left = Math.min(r.right + window.scrollX + 8, window.scrollX + document.documentElement.clientWidth - preview.offsetWidth - 8) + "px";
    preview.style.top = (r.top + window.scrollY - 10) + "px";
  });
  document.addEventListener("mouseout", function (e) {
    if (preview && e.target.closest(".quotelink")) {
      preview.remove();
      preview = null;
    }
  });

  // Highlight the post named in the URL fragment.
  function highlight() {
    document.querySelectorAll(".post.highlight").forEach(function (p) { p.classList.remove("highlight"); });
    var p = location.hash.length > 2 && document.getElementById(location.hash.slice(1));
    if (p && p.classList.contains("reply")) p.classList.add("highlight");
  }
  window.addEventListener("hashchange", highlight);
  highlight();

  // Posting solves a short proof of work; show that something is happening.
  document.querySelectorAll(".postform").forEach(function (f) {
    f.addEventListener("submit", function () {
      var b = f.querySelector('button[type="submit"]');
      b.disabled = true;
      b.textContent = "Signing…";
    });
  });
})();
