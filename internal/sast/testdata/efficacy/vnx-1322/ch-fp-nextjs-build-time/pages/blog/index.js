import fs from 'fs';
import path from 'path';

export async function getStaticProps() {
  const dir = path.join(process.cwd(), 'posts');
  const posts = fs.readdirSync(dir).map((f) => fs.readFileSync(path.join(dir, f), 'utf8'));
  return { props: { posts } };
}

export default function Blog({ posts }) {
  return posts.length;
}
