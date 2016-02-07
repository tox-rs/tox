# Contributing to Tox

We'd love for you to contribute to our source code and to make Tox even better than it is today! Here are the guidelines we'd like you to follow:

- [Issues and Bugs](#issue)
- [Coding Rules](#rules)
- [Commit Guidelines](#commit)
- [Submission Guidelines](#submit)

### Must read
* Use **[commit message format](#commit-message-format)**.
* Keep the title **short** and provide a **clear** description about what your pull request does.
* Keep your git commit history **clean** and **precise**. Commits like `xxx fixup` should not appear.
* If your commit fixes a reported issue (for example #4134), add the following message to the commit `Fixes #4134.`.



## <a name="issue"></a> Found an Issue?
If you find a bug in the source code or a mistake in the documentation, you can help us by submitting an issue to our [GitHub Repository][github]. Even better, you can submit a Pull Request with a fix.



## <a name="rules"></a> Coding Rules
To ensure consistency throughout the source code, keep these rules in mind as you are working:
* All features or bug fixes **must be tested** by one or more tests.
* All functions **must be documented**, *especially* APIs.

* Preferably wrap all the code at **80 characters**, or max 100 if you have to. This is not a *hard* rule - just keep it sane.
* Spaces, 4 of them for an indent level, no tabs.

*This section needs to be improved - if you're interested in doing that, please do.*



## <a name="commit"></a> Git Commit Guidelines

We have very precise rules over how our git commit messages can be formatted.  This leads to **more readable messages** that are easy to follow when looking through the **project history**.  But also, we use the git commit messages to **generate the Tox change log** using [clog-cli](https://github.com/clog-tool/clog-cli).


### Commit Message Format
Each commit message consists of a **header**, a **body** and a **footer**.  The header has a special
format that includes a **type**, a **scope** and a **subject**:

```
<type>(<scope>): <subject>
<BLANK LINE>
<body>
<BLANK LINE>
<footer>
```

The **header** is mandatory and the **scope** of the header is optional.

Any line of the commit message cannot be longer 100 characters! This allows the message to be easier
to read on GitHub as well as in various git tools.

### Revert
If the commit reverts a previous commit, it should begin with `revert: `, followed by the header of the reverted commit. In the body it should say: `This reverts commit <hash>.`, where the hash is the SHA of the commit being reverted.

### Type
Must be one of the following:

* **feat**: A new feature
* **fix**: A bug fix
* **docs**: Documentation only changes
* **style**: Changes that do not affect the meaning of the code (white-space, formatting, missing
  semi-colons, etc)
* **refactor**: A code change that neither fixes a bug nor adds a feature
* **perf**: A code change that improves performance
* **test**: Adding missing tests
* **chore**: Changes to the build process or auxiliary tools and libraries such as documentation
  generation

### Scope
The scope could be anything specifying place of the commit change. For example `$location`,
`$browser`, `$compile`, `$rootScope`, `ngHref`, `ngClick`, `ngView`, etc...

### Subject
The subject contains succinct description of the change:

* use the imperative, present tense: "change" not "changed" nor "changes"
* don't capitalize first letter
* no dot (.) at the end

### Body
Just as in the **subject**, use the imperative, present tense: "change" not "changed" nor "changes".
The body should include the motivation for the change and contrast this with previous behavior.

### Footer
The footer should contain any information about **Breaking Changes** and is also the place to
reference GitHub issues that this commit **Closes**.

**Breaking Changes** should start with the word `BREAKING CHANGE:` with a space or two newlines. The rest of the commit message is then used for this.



## <a name="submit"></a> Submission Guidelines
### Submitting a Pull Request
Before you submit your pull request consider the following guidelines:

* Search [GitHub][github-prs] for an open or closed Pull Request that relates to your submission. You don't want to duplicate effort.
* Make your changes in a new git branch:

     ```shell
     git checkout -b my-fix-branch master
     ```

* Create your patch, **including appropriate test cases**.
* Run the tests: `cargo test`, and ensure that all of them pass.
* Commit your changes using a descriptive commit message that follows our
  [commit message conventions](#commit-message-format). Adherence is required because release notes are automatically generated from these messages.

     ```shell
     git commit -a
     ```
  Note: the optional commit `-a` command line option will automatically "add" and "rm" edited files.

* Push your branch to GitHub:

    ```shell
    git push origin my-fix-branch
    ```

* In GitHub, send a pull request to `zetok:master`.
* If we suggest changes then:
  * Make the required updates.
  * Re-run `cargo test` to ensure test are still passing.
  * Commit your changes to your branch (e.g. `my-fix-branch`).
  * Push the changes to your GitHub repository (this will update your Pull Request).

If the PR gets too outdated we may ask you to rebase and force push to update the PR:

```shell
git rebase master -i
git push origin my-fix-branch -f
```

*WARNING. Squashing or reverting commits and forced push thereafter may remove GitHub comments on code that were previously made by you and others in your commits.*

That's it! Thank you for your contribution!

#### After your pull request is merged

After your pull request is merged, you can safely delete your branch and pull the changes from the main (upstream) repository:

* Delete the remote branch on GitHub either through the GitHub web UI or your local shell as follows:

    ```shell
    git push origin --delete my-fix-branch
    ```

* Check out the master branch:

    ```shell
    git checkout master -f
    ```

* Delete the local branch:

    ```shell
    git branch -D my-fix-branch
    ```

* Update your master with the latest upstream version:

    ```shell
    git pull --ff upstream master
    ```

----
*Note: depending on development, those guidelines should be adjusted & expanded.*


[github]: https://github.com/zetok/tox
[github-prs]: https://github.com/zetok/tox/pulls
