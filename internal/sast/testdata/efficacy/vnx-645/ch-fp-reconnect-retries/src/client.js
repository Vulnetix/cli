class FeedClient {
  onClose() {
    this.retries += 1;
    if (this.retries > MAX_RETRIES) {
      this.enabled = false;
      return;
    }
    setTimeout(() => this.connect(), 1000 * this.retries);
  }
}
