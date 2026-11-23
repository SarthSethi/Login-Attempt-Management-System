# Design diagrams

| File | Diagram |
|---|---|
| `01-use-case` | Use case diagram (actors and features) |
| `02-architecture` | Layered architecture of the Spring Boot application |
| `03-er-diagram` | ER diagram of the eight MySQL tables |
| `04-class-diagram` | Main Java classes and how they depend on each other |
| `05-sequence-failed-login` | Wrong password and the detection rules (locks, blocks, alerts) |
| `06-sequence-blocked-ip` | Correct password from a blocked IP or locked account (rejected before authentication) |
| `07-sequence-successful-login` | Successful login with risk check and session registration |
| `08-activity-blocking-algorithm` | Flowchart of login processing and rules 1-5 |
| `09-dfd-level0` | Data flow diagram, level 0 (context) |
| `10-dfd-level1` | Data flow diagram, level 1 |
| `11-deployment` | Deployment on Render + Aiven |
| `12-state-ip` | States of an IP address (Normal, Watched, Pair-locked, Blocked, Banned, Trusted) |

Each diagram has a `.puml` text source (PlantUML) and a rendered `.png`.
`_style.iuml` holds the shared colours and fonts.

## Editing a diagram

1. Edit the `.puml` file (plain text).
2. Download PlantUML once (a single Java jar):
   <https://repo1.maven.org/maven2/net/sourceforge/plantuml/plantuml/1.2026.9/plantuml-1.2026.9.jar>
3. From this folder, regenerate the pictures:

   ```bash
   java -jar plantuml-1.2026.9.jar -tpng *.puml
   ```

No Graphviz installation is needed (the diagrams use PlantUML's built-in `smetana` layout).
You can also paste a `.puml` file into <https://www.plantuml.com/plantuml> to view it online.
