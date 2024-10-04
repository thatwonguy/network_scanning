# Poetry Guide from A to Z

This guide provides step-by-step instructions on how to use Poetry to manage your Python projects. It covers everything from installing Poetry, setting up a new project, managing dependencies, and running your project in a Poetry-managed environment.

## 1. Installing Poetry

To install Poetry, follow the official installation instructions. Run the following command in your terminal:

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

After installation, ensure that Poetry is added to your system's `PATH`. You can do this by adding the following line to your shell configuration file (`.bashrc`, `.zshrc`, etc.):

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Verify the installation:

```bash
poetry --version
```

## 2. Setting Up a New Project
To create a new project with Poetry, navigate to the directory where you want to create your project and run:

```bash
poetry new my-project
```

This will create a new directory `my-project/` with the following structure:

```perl
my-project/
├── pyproject.toml        # Project configuration file managed by Poetry
├── README.rst            # Default README file in reStructuredText format
├── my_project/           # Source code directory
│   └── __init__.py       # Initializes the Python package
└── tests/                # Directory for your tests
    └── __init__.py
```

Alternatively, if you already have a project, you can initialize Poetry in your project by running:

```bash
cd my-existing-project
poetry init
```

Poetry will prompt you to set up the project configuration, such as project name, version, description, etc.

## 3. Managing Dependencies

Adding Dependencies
To add dependencies to your project, use the `poetry add` command:

```bash
poetry add <package-name>
```

Example:  

```bash
poetry add requests
```

This will install the package and add it to the `pyproject.toml` file under `[tool.poetry.dependencies]`.

Adding Development Dependencies
To add development dependencies (such as linters or testing frameworks), use the `--dev` flag:

```bash
poetry add --dev <package-name>
```

Example: 

```bash
poetry add --dev pytest
```

This will add the package under `[tool.poetry.dev-dependencies]` in your `pyproject.toml` file.

## Updating Dependencies
To update all your project dependencies to their latest versions (while respecting version constraints in pyproject.toml):

```bash
poetry update
```

You can also update specific dependencies:

```bash
poetry update <package-name>
```

## 4. Installing Dependencies

If you have just cloned a project with an existing `pyproject.toml` and `poetry.lock`, you can install all dependencies by running:

```bash
poetry install
```

This will create a virtual environment (if it doesn't exist) and install all dependencies, including locking their versions in `poetry.lock`.

## 5. Activating the Poetry Environment

Poetry manages a virtual environment for your project. You can activate this environment using:

```bash
poetry shell
```

Once inside the shell, any Python commands will be run in the Poetry-managed environment. For example, you can run your scripts like this:

```bash
python src/my_project/main.py
```

To deactivate the shell, simply type:

```bash
exit
```

Alternatively, you can run commands without activating the shell by using:

```bash
poetry run <command>
```

Example:

```bash
poetry run python src/my_project/main.py
```

## 6. Project Structure

Here’s a recommended project structure when using Poetry:

```perl
my-project/
├── pyproject.toml        # Poetry configuration file
├── poetry.lock           # Locked dependency versions (auto-generated)
├── README.md             # Project README file
├── src/                  # Source code directory (recommended for larger projects)
│   └── my_project/       # Your project code
│       ├── __init__.py   # Makes the directory a package
│       ├── main.py       # Entry point for the project
│       └── utils.py      # Other modules
└── tests/                # Test files
    ├── __init__.py
    └── test_main.py      # Unit tests
```

This structure is clear, scalable, and helps avoid issues with imports.

`pyproject.toml`: Defines project dependencies, metadata, and other configurations.  
`poetry.lock`: Ensures consistent dependency versions across environments.  
`src/`: Houses the project’s source code.  
`tests/`: Contains the test suite for your project.  

## 7. Running Your Project

With the Poetry environment activated, you can run your project’s Python scripts using the standard `python` command:

```bash
python src/my_project/main.py
```

Alternatively, you can use `poetry run` to run the script directly without activating the shell:

```bash
poetry run python src/my_project/main.py
```

## 8. Running Tests
If you’ve set up a testing framework like `pytest`, you can run your tests inside the Poetry environment:

```bash
poetry run pytest
```

Or, if you’re inside the Poetry shell:

```bash
pytest
```

## 9. Building and Publishing Your Project

### Building

To build your project (create source and wheel distributions), run:

```bash
poetry build
```

This will generate the build artifacts in the `dist/` directory.

### Publishing

To publish your package to PyPI, run:

```bash
poetry publish
```

Make sure your PyPI credentials are set up. You can also specify an alternative repository:

```bash
poetry publish --repository <repository-name>
```

## 10. Locking and Version Control

### Commit Your `pyproject.toml` and `poetry.lock`

Ensure that both `pyproject.toml` and `poetry.lock` are committed to version control. This allows you and your collaborators to have consistent environments.

Add them to Git:

```bash
git add pyproject.toml poetry.lock
git commit -m "Add Poetry configuration and lock files"
```

#### `.gitignore`

Make sure to exclude the following from version control:

```bash
# .gitignore
.venv/
__pycache__/
*.pyc
*.pyo
```

Poetry generally manages the virtual environment outside your project directory, so it’s usually safe not to include `.venv/` in the repository.

## Conclusion

Poetry simplifies Python dependency management and project packaging by combining functionality that previously required multiple tools. Whether you are working on a small script or a large project, Poetry helps ensure consistent environments, easy dependency management, and a simple workflow for building and publishing Python projects.
