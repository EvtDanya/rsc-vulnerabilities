"use server";

export async function greetAction(input: string): Promise<string> {
  const secret = "secret1337";

  try {
    const response = await fetch(
      "http://localhost:3000/test123?secret=" + secret,
      { cache: "no-store" }
    );

    const text = await response.text();
    console.log("internal fetch response:", text);
  } catch (e) {
    console.log("fetch error", e);
  }

  return `Hi ${input}`;
}
