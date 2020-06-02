import { Enforcer, newEnforcer, DefaultRoleManager, Model } from "casbin";

class MyEnforcer {
  modelString: string = `
  [request_definition]
  r = sub, obj, act, dom
  
  [policy_definition]
  p = sub, obj, act
  
  [role_definition]
  g = _, _, _
  
  [policy_effect]
  e = some(where (p.eft == allow))
  
  [matchers]
  m = (g(r.sub, p.sub, r.dom) || g(r.sub, p.sub, "all")) && r.obj == p.obj && r.act == p.act
  `;
  model: Model;
  enforcer: Enforcer;
  constructor() {
    this.initialize().then(async () => {
      console.log("Initialization over.");
      await this.configure();
      await this.testUser("a", "write", "rb", ".*");
    });
  }

  public async initialize() {
    this.model = new Model();
    this.model.loadModelFromText(this.modelString);
    this.enforcer = await newEnforcer(this.model);
    this.enforcer.enableLog(true);

    const rm = new DefaultRoleManager(10);
    rm.addMatchingFunc("matcher", (arg1, arg2) => {
      const regexGroup = new RegExp(arg1);
      return regexGroup.test(arg2);
    });

    this.enforcer.setRoleManager(rm);
    await this.enforcer.buildRoleLinks();
  }

  public configure() {
    //   this.enforcer.addFunction('regexGroup')

    this.enforcer.addPolicy("user", "rb", "write");
    this.enforcer.addPolicy("admin", "rb", "read");
    this.enforcer.addGroupingPolicy("a", "user", "180");
    this.enforcer.addGroupingPolicy("a", "admin", "all");
    this.enforcer.addGroupingPolicy("b", "user", "1000");
  }

  public async testUser(
    username: string,
    action: string,
    object: string,
    domain: string
  ) {
    // const permissions = await this.enforcer.enforce(
    //   username,
    //   object,
    //   action,
    //   domain
    // );
    // // const a = this.enforcer.getRoleManager();
    // console.log("Permissions: ", { permissions });
    console.log(
      "Grouping policies: ",
      await this.enforcer.getGroupingPolicy(),
      "\n"
    );
    const groupingPolicies = await this.enforcer.getFilteredGroupingPolicy(
      0,
      "a",
      "",
      ""
    );

    const allowed = await this.enforcer.enforce(
      username,
      object,
      action,
      domain
    );
    console.log("Implicit roles: ", groupingPolicies, "\n");

    const permissions = [];

    for (const groupingPolicy of groupingPolicies) {
      const permission = await this.enforcer.getFilteredPolicy(
        0,
        groupingPolicy[1]
      );
      permissions.push(permission);
    }

    console.log("Permissions", permissions);
  }
}

const myEnforcer = new MyEnforcer();
