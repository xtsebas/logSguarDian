/**
 * Regression coverage for cli.ts's own command-dispatch switch.
 *
 * Every other cli-*.test.ts file calls a `run*` handler directly — none of
 * them ever go through cli.ts's actual switch, which is exactly how the
 * "webhooks test" case's missing `break;` (falling through into "webhooks
 * list") shipped undetected: the bug lived in the dispatch itself, not in
 * either handler.
 *
 * All handler modules are mocked; cli.ts is re-required inside
 * jest.isolateModules() per case so its top-level switch (which only runs
 * once per module load) actually re-executes for each command under test.
 */

jest.mock("../src/cli/config-init", () => ({ runConfigInit: jest.fn() }));
jest.mock("../src/cli/config-show", () => ({ runConfigShow: jest.fn() }));
jest.mock("../src/cli/config-set", () => ({ runConfigSet: jest.fn() }));
jest.mock("../src/cli/config-validate", () => ({ runConfigValidate: jest.fn() }));
jest.mock("../src/cli/attacks-list", () => ({ runAttacksList: jest.fn() }));
jest.mock("../src/cli/attacks-summary", () => ({ runAttacksSummary: jest.fn() }));
jest.mock("../src/cli/attacks-inspect", () => ({ runAttacksInspect: jest.fn() }));
jest.mock("../src/cli/endpoints-top", () => ({ runEndpointsTop: jest.fn() }));
jest.mock("../src/cli/endpoints-profile", () => ({ runEndpointsProfile: jest.fn() }));
jest.mock("../src/cli/endpoints-report", () => ({ runEndpointsReport: jest.fn() }));
jest.mock("../src/cli/webhooks-add", () => ({ runWebhooksAdd: jest.fn() }));
jest.mock("../src/cli/webhooks-remove", () => ({ runWebhooksRemove: jest.fn() }));
jest.mock("../src/cli/webhooks-test", () => ({ runWebhooksTest: jest.fn().mockResolvedValue(undefined) }));
jest.mock("../src/cli/webhooks-list", () => ({ runWebhooksList: jest.fn() }));
jest.mock("../src/cli/guard", () => ({ requireConfig: jest.fn() }));

const originalArgv = process.argv;

afterEach(() => {
  process.argv = originalArgv;
});

/** Runs cli.ts fresh against the given argv tail, inside an isolated module
 *  registry, and returns the mocked handler modules from that SAME registry
 *  (grabbing them from outside isolateModules would return a different,
 *  never-called set of mock instances). */
function runCli(args: string[]) {
  process.argv = ["node", "logsguardian", ...args];
  let handlers!: {
    webhooksTest: typeof import("../src/cli/webhooks-test");
    webhooksList: typeof import("../src/cli/webhooks-list");
    configShow: typeof import("../src/cli/config-show");
  };
  jest.isolateModules(() => {
    require("../src/cli");
    handlers = {
      webhooksTest: require("../src/cli/webhooks-test"),
      webhooksList: require("../src/cli/webhooks-list"),
      configShow: require("../src/cli/config-show"),
    };
  });
  return handlers;
}

describe("cli.ts — command dispatch", () => {
  test("sanity: a known-simple command dispatches to its own handler", () => {
    const { configShow } = runCli(["config", "show"]);
    expect(configShow.runConfigShow).toHaveBeenCalledWith([]);
  });

  test("'webhooks test <id>' dispatches to runWebhooksTest only — does not also run webhooks list", () => {
    const { webhooksTest, webhooksList } = runCli(["webhooks", "test", "1"]);
    expect(webhooksTest.runWebhooksTest).toHaveBeenCalledWith(["1"]);
    expect(webhooksList.runWebhooksList).not.toHaveBeenCalled();
  });

  test("'webhooks list' on its own still dispatches to runWebhooksList", () => {
    const { webhooksList } = runCli(["webhooks", "list"]);
    expect(webhooksList.runWebhooksList).toHaveBeenCalledWith([]);
  });
});
