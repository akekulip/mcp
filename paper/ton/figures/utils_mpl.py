"""
Collection of small utils to create figures with Matplotlib:
    - Setup nice default parameters (fonts, sizes, etc.).
    - Create and save figures as PDFs and PNGs.
    - Set the grid, axis limit, and axis ticks.
    - Clone the exact size of an axes in a new figure.
"""

__author__ = "Thomas Guillod"
__copyright__ = "Thomas Guillod - Dartmouth College"
__license__ = "Mozilla Public License Version 2.0"

import matplotlib.pyplot as plt
import matplotlib.ticker as tkr
import numpy as np


def set_global():
    """
    Set the global Matplotlib options.
    """

    # set the font family
    plt.rcParams["font.size"] = 9.0
    plt.rcParams["font.family"] = "Times New Roman"
    plt.rcParams["mathtext.default"] = "regular"

    # set the axes parameters
    plt.rcParams["axes.linewidth"] = 1.0
    plt.rcParams["axes.labelsize"] = 9.0
    plt.rcParams["axes.titlesize"] = 10.0
    plt.rcParams["axes.labelpad"] = 8.0
    plt.rcParams["axes.labelweight"] = "bold"
    plt.rcParams["axes.titleweight"] = "bold"

    # set the legend parameters
    plt.rcParams["legend.edgecolor"] = "k"
    plt.rcParams["legend.fancybox"] = False
    plt.rcParams["legend.framealpha"] = 1.0
    plt.rcParams["legend.fontsize"] = 9.0


def set_grid(fig, ax, major=True, minor=True):
    """
    Set the grid for a plot.

    Parameters
    ----------
    fig : figure
        Matplotlib figure.
    ax : axes
        Matplotlib axes to be considered.
    major : bool
        Use the major grid.
    minor : bool
        Use the minor grid.
    """

    if major:
        ax.grid(which="major", linewidth=0.75)
    if minor:
        ax.grid(which="minor", linewidth=0.25)
    fig.tight_layout()


def get_bnd(bnd=None, margin=0.0, log=False):
    """
    Get bound limits with specified tolerances.

    Parameters
    ----------
    bnd : array
        Array with the min and max values.
    margin : float
        Relative margin for the bounds.
    log : float
        Determine if the axis is linear or logarithmic.

    Returns
    -------
    v_min : float
        Lower limit for the axis.
    v_max : float
        Upper limit for the axis.
    """

    # scale the axis
    if log:
        bnd = np.log10(bnd)

    # find the bounds
    add_offset = (np.max(bnd) - np.min(bnd)) * margin
    v_min = np.min(bnd) - add_offset
    v_max = np.max(bnd) + add_offset

    # unscale the axis
    if log:
        v_min = np.power(10.0, v_min)
        v_max = np.power(10.0, v_max)

    return v_min, v_max


def set_cbar(obj, bnd=None, margin=0.0, log=False):
    """
    Create a colorbar and set the bounds (with tolerances).

    Parameters
    ----------
    obj : map
        Mappable where the color limit is set.
    bnd : array
        Array with the min and max values.
    margin : float
        Relative margin for the bounds.
    log : float
        Determine if the axis is linear or logarithmic.
    """

    if bnd is not None:
        (v_min, v_max) = get_bnd(bnd=bnd, margin=margin, log=log)
        obj.set_clim(v_min, v_max)


def set_x_axis(ax, bnd=None, margin=0.0, log=False):
    """
    Set the bounds for the x-axis (with tolerances).

    Parameters
    ----------
    ax : axes
        Matplotlib axes to be considered.
    bnd : array
        Array with the min and max values.
    margin : float
        Relative margin for the bounds.
    log : float
        Determine if the axis is linear or logarithmic.
    """

    if bnd is not None:
        (v_min, v_max) = get_bnd(bnd=bnd, margin=margin, log=log)
        ax.set_xlim(v_min, v_max)


def set_y_axis(ax, bnd=None, margin=0.0, log=False):
    """
    Set the bounds for the y-axis (with tolerances).

    Parameters
    ----------
    ax : axes
        Matplotlib axes to be considered.
    bnd : array
        Array with the min and max values.
    margin : float
        Relative margin for the bounds.
    log : float
        Determine if the axis is linear or logarithmic.
    """

    if bnd is not None:
        (v_min, v_max) = get_bnd(bnd=bnd, margin=margin, log=log)
        ax.set_ylim(v_min, v_max)


def set_format(axis, ticks=None, fmt=None):
    """
    Set the tick locations and formats with the following options:
        - A Matplotlib formatter can be provided.
        - If a string is provided, StrMethodFormatter is used.
        - If a calltable is provided, FuncFormatter is used.

    Parameters
    ----------
    axis : axis
        Axis to be considered.
    ticks : array
        Position of the ticks.
    fmt : format
        Tick formatter (Formatter object, string, or function handle).
    """

    # set the ticks
    if ticks is not None:
        axis.set_ticks(ticks)

    # set the format
    if fmt is not None:
        if isinstance(fmt, tkr.Formatter):
            axis.set_major_formatter(fmt)
        elif isinstance(fmt, str):
            axis.set_major_formatter(tkr.StrMethodFormatter(fmt))
        elif callable(fmt):
            axis.set_major_formatter(tkr.FuncFormatter(fmt))
        else:
            raise ValueError("invalid tick format")


def get_fig(size=(6, 4), dpi=100):
    """
    Create a figure for a vector plot.

    Parameters
    ----------
    size : tuple
        Size of the figure in inches.
    dpi : int
        Resolution of the figure in dpi.

    Returns
    -------
    fig : figure
        Matplotlib figure.
    ax : axes
        Matplotlib axes.
    """

    # create the figure
    fig = plt.figure(figsize=size, dpi=dpi)
    ax = fig.gca()

    return fig, ax


def get_fig_clone(fig, ax):
    """
    Find the exact dimension (width and height) of the axes.
    Find the bounds of the axes (x-axis, y-axis, and colorbar).

    This function is used to split large plots in two parts:
        - A vector plot with the axes, labels, ticks, legend, etc.
        - A raster plot with the large payload (contour, scatter, etc.)

    Parameters
    ----------
    fig : figure
        Matplotlib figure to be considered.
    ax : axes
        Matplotlib axes to be considered.

    Returns
    -------
    size : tuple
        Size of the figure in inches.
    xlim : tuple
        Limit for the x-axis.
    ylim : tuple
        Limit for the y-axis.
    """

    # get the size of the axis of the vector figure
    bbox = ax.get_window_extent()
    width = bbox.width / fig.dpi
    height = bbox.height / fig.dpi

    size = (width, height)
    xlim = ax.get_xlim()
    ylim = ax.get_ylim()

    return size, xlim, ylim


def set_fig_clone(fig, ax, size, xlim, ylim):
    """
    Resize a figure to the specified dimensions.
    The axes are occupied the complete figure.
    The axes and grid are hidden.

    This function is used to split large plots in two parts:
        - A vector plot with the axes, labels, ticks, legend, etc.
        - A raster plot with the large payload (e.g., contour, scatter, or image).

    Parameters
    ----------
    fig : figure
        Matplotlib figure to be considered.
    ax : axes
        Matplotlib axes to be considered.
    size : tuple
        Size of the figure in inches.
    xlim : tuple
        Limit for the x-axis.
    ylim : tuple
        Limit for the y-axis.
    """

    # set the axes
    fig.set_size_inches(size)
    ax.set_position([0.0, 0.0, 1.0, 1.0])

    # set the extent
    plt.xlim(xlim)
    plt.ylim(ylim)
    plt.grid(False)
    plt.axis(False)


def save_svg(fig, filename):
    """
    Save a plot to an SVG file.

    Parameters
    ----------
    fig : figure
        Matplotlib figure to be saved.
    filename : str
        Path of the filename to be saved.
    """

    fig.savefig(filename, transparent=True)


def save_png(fig, filename, dpi=100):
    """
    Save a plot to a PNG file.

    Parameters
    ----------
    fig : figure
        Matplotlib figure to be saved.
    filename : str
        Path of the filename to be saved.
    dpi : int
        Resolution (in dpi) for the export.
    """

    fig.savefig(filename, dpi=dpi, transparent=True)
