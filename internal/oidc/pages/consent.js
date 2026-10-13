(function () {
  var form = document.getElementById("consent-form");
  var decision = document.getElementById("decision");
  var allow = document.getElementById("allow-btn");
  var deny = document.getElementById("deny-btn");
  if (!form || !decision) return;

  function choose(value) {
    decision.value = value;
  }

  if (allow) {
    allow.addEventListener("click", function () {
      choose("allow");
    });
  }
  if (deny) {
    deny.addEventListener("click", function () {
      choose("deny");
    });
  }
})();
