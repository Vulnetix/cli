<script>
  async function submit() {
    const res = await fetch("/api/session", { method: "POST" });
    const { jwt } = await res.json();
~>    localStorage.setItem("jwt", jwt);
  }
</script>

<button on:click={submit}>Sign in</button>
