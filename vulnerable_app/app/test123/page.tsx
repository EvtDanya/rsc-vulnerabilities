import { greetAction } from "../action";

export default function TestPage() {
  return (
    <main style={{ padding: 32 }}>
      <h1>/test123</h1>

      <form action={greetAction}>
        <input
          name="input"
          defaultValue="test"
          style={{ border: "1px solid #ccc", padding: 4 }}
        />
        <button type="submit">Send</button>
      </form>
    </main>
  );
}
