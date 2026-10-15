import React from 'react';

export class Embed extends React.Component {
  componentDidMount() {
~>    window.addEventListener('message', this.handleMessage);
  }

  handleMessage(event) {
    this.setState({ html: event.data.html });
  }

  render() {
    return <div dangerouslySetInnerHTML={{ __html: this.state.html }} />;
  }
}

~>window.addEventListener('message', async ({ data }) => {
  await fetch(data.url, { method: 'POST' });
});
