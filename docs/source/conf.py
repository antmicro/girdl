# -*- coding: utf-8 -*-

from datetime import datetime

from antmicro_sphinx_utils.defaults import (
    numfig_format,
    extensions as default_extensions,
    myst_enable_extensions as default_myst_enable_extensions,
    myst_fence_as_directive as default_myst_fence_as_directive,
    antmicro_html,
    antmicro_latex
)

# General information about the project.
project = u'girdl Plugin'
basic_filename = u'girdl-docs'
authors = u'Antmicro'
copyright = f'{authors}, {datetime.now().year}'

version = '1.0'
release = version

# This is temporary before the clash between myst-parser and immaterial is fixed
sphinx_immaterial_override_builtin_admonitions = False

numfig = True

# If you need to add extensions just add to those lists
extensions = default_extensions
myst_enable_extensions = default_myst_enable_extensions
myst_fence_as_directive = default_myst_fence_as_directive

myst_substitutions = {
    "project": project
}

myst_heading_anchors = 4
today_fmt = '%Y-%m-%d'
todo_include_todos=False

# -- Options for HTML output ---------------------------------------------------

html_theme = 'sphinx_immaterial'

html_last_updated_fmt = today_fmt

html_show_sphinx = False

(
    html_logo,
    html_theme_options,
    html_context
) = antmicro_html()

html_title = project

(
    latex_elements,
    latex_documents,
    latex_logo,
    latex_additional_files
) = antmicro_latex(basic_filename, authors, project)
