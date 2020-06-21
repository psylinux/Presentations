%% -------------------------------------------------------------------------
%%
%% LaTeX document class for typesetting thesis
%% Instituto de Informática - Universidade Federal de Goiás
%%
%% Any modified versions of this file must be renamed
%% with new filenames distinct from `inf-ufg.cls'
%%
%% -------------------------------------------------------------------------
%%
%% \CharacterTable
%%  {Upper-case    \A\B\C\D\E\F\G\H\I\J\K\L\M\N\O\P\Q\R\S\T\U\V\W\X\Y\Z
%%   Lower-case    \a\b\c\d\e\f\g\h\i\j\k\l\m\n\o\p\q\r\s\t\u\v\w\x\y\z
%%   Digits        \0\1\2\3\4\5\6\7\8\9
%%   Exclamation   \!     Double quote  \"     Hash (number) \#
%%   Dollar        \$     Percent       \%     Ampersand     \&
%%   Acute accent  \'     Left paren    \(     Right paren   \)
%%   Asterisk      \*     Plus          \+     Comma         \,
%%   Minus         \-     Point         \.     Solidus       \/
%%   Colon         \:     Semicolon     \;     Less than     \<
%%   Equals        \=     Greater than  \>     Question mark \?
%%   Commercial at \@     Left bracket  \[     Backslash     \\
%%   Right bracket \]     Circumflex    \^     Underscore    \_
%%   Grave accent  \`     Left brace    \{     Vertical bar  \|
%%   Right brace   \}     Tilde         \~}
%%
%% ----------------------------------------------------------------------------


%%======================================================================
%% inf-ufg Class Identification
%%======================================================================
\newcommand{\docdate}{}  % See the renewcommands below,
\newcommand{\filedate}{} % these contain the content;-))
\newcommand{\fileversion}{}
\renewcommand{\docdate}{2007/05/30}
\renewcommand{\filedate}{2007/05/30}
\renewcommand{\fileversion}{1.4}
\NeedsTeXFormat{LaTeX2e}[1999/12/01]
\ProvidesClass{inf-ufg}%
[\filedate\space v\fileversion\space INF-UFG Thesis Class]
\typeout{LaTeX 2e package inf-ufg' -- Released 30 May 2007}

%%======================================================================
%% inf-ufg Class Options
%%======================================================================
\RequirePackage{ifthen}

\newboolean{tese} \setboolean{tese}{false}
\newboolean{diss} \setboolean{diss}{true}
\newboolean{mngr} \setboolean{mngr}{false}
\newboolean{rtcc} \setboolean{rtcc}{false}
\newboolean{abnt} \setboolean{abnt}{false}
\newboolean{link} \setboolean{link}{false}

\DeclareOption{tese}{
 \setboolean{tese}{true}
 \setboolean{diss}{false}
 \setboolean{mngr}{false}
 \setboolean{rtcc}{false}}

\DeclareOption{dissertacao}{
 \setboolean{tese}{false}
 \setboolean{diss}{true}
 \setboolean{mngr}{false}
 \setboolean{rtcc}{false}}

\DeclareOption{monografia}{
 \setboolean{tese}{false}
 \setboolean{diss}{false}
 \setboolean{mngr}{true}
 \setboolean{rtcc}{false}}

\DeclareOption{relatorio}{
 \setboolean{tese}{false}
 \setboolean{diss}{false}
 \setboolean{mngr}{false}
 \setboolean{rtcc}{true}}

\DeclareOption{abnt}{
 \setboolean{abnt}{true}}

\DeclareOption{nocolorlinks}{
 \setboolean{link}{true}}

\DeclareOption{american,english,french,german,brazil,portuguese}{
 \PassOptionsToPackage{\CurrentOption}{babel,fancyref}}

\ProcessOptions\relax

\def\titulo#1{\def\@titulo{#1}}                 \titulo{}
\def\subtitulo#1{\def\@subtitulo{#1}}           \subtitulo{}
\def\autor#1{\def\@autor{#1}}                   \autor{}
\def\autorR#1{\def\@autorR{#1}}                 \autorR{}
\def\orientador#1{\def\@orientador{#1}}         \orientador{}
\def\orientadora#1{\def\@orientadora{#1}}       \orientadora{}
\def\orientadorR#1{\def\@orientadorR{#1}}       \orientadorR{}
\def\orientadoraR#1{\def\@orientadoraR{#1}}     \orientadoraR{}
\def\coorientador#1{\def\@coorientador{#1}}     \coorientador{}
\def\coorientadora#1{\def\@coorientadora{#1}}   \coorientadora{}
\def\coorientadorR#1{\def\@coorientadorR{#1}}   \coorientadorR{}
\def\coorientadoraR#1{\def\@coorientadoraR{#1}} \coorientadoraR{}
\def\chaves#1{\def\@chaves{#1}}                 \chaves{}
\def\keys#1{\def\@keys{#1}}                     \keys{}
\def\dia#1{\def\@dia{#1}}                       \dia{}
\def\mes#1{\def\@mes{#1}}                       \mes{\month}
\def\@mesP{
  \ifcase\@mes\or
    Janeiro\or Fevereiro\or Mar\c{c}o\or 
    Abril\or Maio\or Junho\or 
    Julho\or Agosto\or Setembro\or 
    Outubro\or Novembro\or Dezembro\fi}
\def\ano#1{\def\@ano{#1}}                       \ano{}
\def\cidade#1{\def\@cidade{#1}}                 \cidade{Goi\^ania}
\def\departamento#1{\def\@departamento{#1}}     \departamento{}
\def\unidadeco#1{\def\@unidadeco{#1}}           \unidadeco{Instituto de Inform\'atica}
\def\programa#1{\def\@programa{#1}}             \programa{Computa\c{c}\~ao}
\def\unidade#1{\def\@unidade{#1}}               \unidade{Instituto de Inform\'atica}
\def\universidade#1{\def\@universidade{#1}}     \universidade{Universidade Federal de Goi\'as}
\def\universidadeco#1{\def\@universidadeco{#1}} \universidadeco{Universidade Federal de Goi\'as}
\def\uni#1{\def\@uni{#1}}                       \uni{UFG}
\def\unico#1{\def\@unico{#1}}                   \unico{UFG}
\def\concentracao#1{\def\@concentracao{#1}}     \concentracao{Otimiza\c c\~ao}


%%======================================================================
%% inf-ufg Class Preliminary Declarations
%%======================================================================
\LoadClass[a4paper,12pt]{report}
\RequirePackage{texnames}


% Nova Lista de Códigos
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\usepackage{listings}
\renewcommand{\lstlistingname}{C\'{o}digo}
\renewcommand{\lstlistlistingname}{Lista de C\'{o}digos de Programas}
\lstset{numbers=left,
stepnumber=1,
firstnumber=1,
numberstyle=\tiny,
extendedchars=true,
breaklines=true,
frame=tb,
basicstyle=\footnotesize,
stringstyle=\ttfamily,
showstringspaces=false
}

% Hyphenation
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\RequirePackage[english,portuguese,brazil]{babel} %Termos pré-definidos em Português
\RequirePackage[LY1]{fontenc}                      %Hifenização correta em Português
\RequirePackage[ansinew]{inputenc}                %Inserção de acentos

%% Fontes adicionais
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\RequirePackage{amsfonts}
\RequirePackage{pslatex}
\newcommand{\arial}{\sf}

%% Verbatim
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\RequirePackage{fancyvrb}

%% Page layout
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\RequirePackage{indentfirst}
\RequirePackage{setspace}

% Referências cruzadas
% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\RequirePackage{ifpdf} % running on pdfTeX?
\ifpdf
 \RequirePackage[hyperref,pdftex]{hyperref}
 \pdfadjustspacing=1    %%% force LaTeX-like character spacing
\else
 \RequirePackage[dvips,breaklinks]{hyperref}
\fi

\hypersetup{
 bookmarksopen=false,
 bookmarksnumbered=true,
 pdfstartview=FitH,
 hypertexnames=false,
 naturalnames=true,
%  pdftitle={<Título do Texto>},
%  pdfauthor={<Nome do Autor,> <email@unidade.ufg.br>},
%  pdfsubject={<Área do conhecimento abordada no texto>}
}

\ifthenelse{\boolean{link}}
{}
{\hypersetup{
 colorlinks=true,
 linkcolor=blue, %%% Color for normal internal links.
 citecolor=blue, %%% Color for bibliographical citations in text.
 urlcolor=blue,  %%% Color for linked URLs.
 filecolor=blue, %%% Color for URLs which open local files.
}}

% Figures
% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\ifpdf
 \RequirePackage[pdftex]{graphicx}
 \DeclareGraphicsExtensions{.jpg, .pdf, .mps, .png}
\else
 \RequirePackage[dvips]{graphicx}
\fi
\RequirePackage[small,bf,up,format=hang,width=.75\textwidth]{caption}
\renewcommand{\captionfont}{\small\itshape}
\setlength{\abovecaptionskip}{0.5\abovecaptionskip}
\setlength{\belowcaptionskip}{0.5\belowcaptionskip}

%% Subfigures
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\RequirePackage[FIGBOTCAP,TABBOTCAP]{subfigure}
% \newcommand{\goodgap}{\hspace{\subfigtopskip}\hspace{\subfigbottomskip}}
\renewcommand{\thesubfigure}{(\alph{subfigure})}
\renewcommand{\@thesubfigure}{\thesubfigure}
% \renewcommand{\p@subfigure}{}
\subfiglabelskip=0pt

%% algorithms
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\RequirePackage[ruled, algo2e, vlined, portugues, algochapter]{algorithm2e}

%% Code lists
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\RequirePackage{float}
\floatstyle{ruled}  %%% options: plain, boxed, ruled
\newfloat{codigo}{htbp}{loc}[chapter] %% numera captions com número de seção.
\floatname{codigo}{C\'{o}digo}
\newcommand{\listofcodes}{\listof{codigo}{Lista de C\'{o}digos de Programas}} %% nome para o sumário

%%======================================================================
%% Declarations
%%======================================================================

%% Page layout
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\setlength{\textwidth}{15cm}
\setlength{\oddsidemargin}{4.0cm}
\addtolength{\oddsidemargin}{-1in}
\addtolength{\oddsidemargin}{-\hoffset}
\addtolength{\oddsidemargin}{-\marginparsep}

\setlength{\headheight}{22.5pt}
\setlength{\voffset}{-1in}
\setlength{\headsep}{3cm}
\addtolength{\headsep}{-1in}
\addtolength{\headsep}{-\voffset}
\addtolength{\headsep}{-\topmargin}
\addtolength{\headsep}{-\headheight}
\setlength{\textheight}{\paperheight}
\addtolength{\textheight}{-\headsep}
\addtolength{\textheight}{-1in}
\addtolength{\textheight}{-\voffset}
\addtolength{\textheight}{-\topmargin}
\addtolength{\textheight}{-\headheight}
\addtolength{\textheight}{-2.5cm}
\setlength{\parindent}{1.5cm}
\addtolength{\skip\footins}{15pt}

%% line spacing
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\onehalfspacing
\frenchspacing
\clubpenalty=2000
\emergencystretch=20pt
\pretolerance=500
\tolerance=2500
\widowpenalty=2000

%% number of floats per page
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\renewcommand\floatpagefraction{.7}
\renewcommand\topfraction{.7}
\renewcommand\bottomfraction{.7}
\renewcommand\textfraction{.3}
\setcounter{totalnumber}{10}
\setcounter{topnumber}{10}
\setcounter{bottomnumber}{10}

%% Section titles
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\def\mghrulefill#1{\leavevmode\leaders\hrule\@height #1\hfill\kern\z@}

\def\@makechapterhead#1{%
  \vspace*{20\p@}%
   {\interlinepenalty\@M
    \raggedleft
    \mghrulefill{0.5pt}
    \Large\sf\mdseries\MakeUppercase{\@chapapp}\space\Huge\thechapter
    \par\nobreak
    \raggedright\LARGE\rm\bfseries #1 \par\nobreak\vskip -10\p@
    \mghrulefill{0.5pt}\par\nobreak
    \vskip 40\p@
  }}

\def\@schapter#1{\if@twocolumn
                   \@topnewpage[\@makeschapterhead{#1}]%
                 \else
                   \@makeschapterhead{#1}%
                   \@afterheading
                 \fi}

\def\@makeschapterhead#1{%
   \vspace*{20\p@}%
  { \parindent \z@ \raggedright
    \interlinepenalty\@M
    \mghrulefill{0.5pt}\par\nobreak
    \raggedright\Large\rm\bfseries #1 \par\nobreak \vskip -10\p@
    \mghrulefill{0.5pt}\par\nobreak
    \vskip 40\p@
  }}

\newcounter{subsubsubsection}[subsubsection]
\def\subsubsubsectionmark#1{}
\def\thesubsubsubsection {\thesubsubsection\arabic{subsubsubsection}}
\def\subsubsubsection{\@startsection
{subsubsubsection}{4}{\z@} {
   -3.25ex plus -1 ex minus -.2ex}{1.5ex plus .2ex}{\normalsize\it}}
\def\l@subsubsubsection{\@dottedtocline{4}{4.8em}{4.2em}}


%% header and footer
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\RequirePackage{fancyhdr}
\fancyhf{} % delete current setting for header and footer

\renewcommand{\sectionmark}[1]{ \markright{\thesection\ #1}{}}
\fancyhead[L]{\footnotesize \nouppercase{\rightmark}}
\fancyhead[R]{\footnotesize \thepage}
\renewcommand{\headrulewidth}{0.5pt}
\fancypagestyle{plain}{\fancyhead{} \fancyfoot{} \renewcommand{\headrulewidth}{0pt}}

\newcommand{\apendices}{
\cleardoublepage
\rm
\appendix
\fancyhead[L]{\footnotesize \nouppercase{\@chapapp}\space\thechapter}
}

%% table of contents
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\RequirePackage[nottoc]{tocbibind}
\RequirePackage[titles]{tocloft}
\RequirePackage{titletoc}
\setcounter{tocdepth}{3}
\setcounter{lofdepth}{2}
\setcounter{lotdepth}{2}
\renewcommand\cfttoctitlefont{\large \arial \bfseries}
\renewcommand\cftloftitlefont{\large \arial \bfseries}
\renewcommand\cftlottitlefont{\large \arial \bfseries}
\setlength{\cftbeforetoctitleskip}{0pt}
\setlength{\cftbeforeloftitleskip}{0pt}
\setlength{\cftbeforelottitleskip}{0pt}
\renewcommand{\@dotsep}{\cftnodots}
\renewcommand{\cftdot}{}
\renewcommand\cftsecfont{}
\setlength{\cftbeforesecskip}{\parskip}
% \setlength{\cftbeforesubsecskip}{\parskip}
% \setlength{\cftbeforesubsubsecskip}{\parskip}
\setlength{\cftbeforesubsecskip}{0pt}
\renewcommand{\cftchapindent}{0pt}
\renewcommand{\cftsecindent}{18pt}
\renewcommand{\cftsubsecindent}{46pt}
\renewcommand{\cftchapfont}{\arial}
\renewcommand{\cftsecfont}{\arial\small}
\renewcommand{\cftsubsecfont}{\arial\footnotesize}
\renewcommand{\cftsubsubsecfont}{\arial\footnotesize}
\renewcommand{\cftfigfont}{\arial}
\renewcommand{\cfttabfont}{\arial}

%% theorems environments
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\renewcommand{\theequation}{\thechapter-\arabic{equation}}
\newtheorem{definition}{Defini\c{c}\~{a}o}[chapter]
\newtheorem{theorem}[definition]{Teorema}
\newtheorem{corollary}[definition]{Corol\'{a}rio}
\newtheorem{lemma}[definition]{Lema}
\newtheorem{proposition}[definition]{Proposi\c{c}\~{a}o}
\newtheorem{comment}[definition]{Observac{c}\~{a}o}
\newenvironment{proof}{\par \noindent \textit{Prova}.}{\hfill $\Box$\newline}

%% itemize environment
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\RequirePackage{atbeginend}
\AfterBegin{itemize}{\addtolength{\itemsep}{-0.5em}}
\AfterBegin{itemize}{\setlength{\parskip}{0pt}}

\renewcommand{\cleardoublepage}{
 \clearpage\if@twoside \ifodd\c@page\else
 \thispagestyle{empty}
 \hbox{}\newpage\if@twocolumn\hbox{}\newpage\fi\fi\fi}

%%======================================================================
%% Pre-textual elements
%%======================================================================
\makeatletter

\newcommand{\margem}[1]{\hspace{0.5cm}\begin{minipage}[top]{13.0cm}#1\end{minipage}}
\newcommand{\textoC}[2]{\begin{center}\linespread{#1}#2\end{center}}
\newcommand{\textoF}[1]{\begin{minipage}[top]{12.0cm}#1\end{minipage}}
\newcommand{\textoD}[1]{\margem{\begin{flushright}#1\end{flushright}}}
\newcommand{\margemD}[1]{\hspace{3.5cm}\begin{minipage}[top]{10cm}#1\end{minipage}}

%% Capa
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\newcommand{\capa}{%
 \ifpdf
  \pdfbookmark[0]{Elementos Pré-Textuais}{pretexto}
  \pdfbookmark[1]{Capa}{pretexto.1}
 \fi
 \hypersetup{
  pdftitle={\@titulo~~\@subtitulo},
  pdfauthor={\@autor},
  pdfsubject={\@concentracao}
 }
 \pagenumbering{roman}
 \singlespacing%
 \begin{titlepage}%
  \textoC{1}{\Large \scshape \@universidade \normalsize \upshape}%
   \vspace*{\stretch{-0.8}}%
  \textoC{1}{\Large \scshape \@unidade \normalsize \upshape}%
  \ifthenelse{\equal{\@departamento}{}}{}{%
   \vspace*{\stretch{-0.8}}%
   \textoC{1}{\Large \scshape \@departamento\relax \normalsize \upshape} }%
  \vspace*{\stretch{.1}}%
  \textoC{1}{\Large \scshape \@autor \normalsize \upshape}%
  \vspace*{\stretch{8}}%
  \textoC{1.8}{\huge \textbf{\@titulo\relax} \normalsize}%
  \ifthenelse{\equal{\@subtitulo}{}}{}{%
   \textoC{1.3}{\Large \textbf{\@subtitulo\relax} \normalsize} }%
  \vspace*{\stretch{9}}%
  \textoC{1}{\@cidade \\ \@ano}%
 \end{titlepage}%
 \onehalfspacing%
 \normalfont%
}%


%% Folha de rosto
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\newcommand{\rosto}{%
 \ifpdf
  \pdfbookmark[1]{Folha de Rosto}{pretexto.2}
 \fi
 \singlespacing%
 \textoC{1}{\Large \scshape \@autor \normalsize \upshape}%
 \vspace*{\stretch{6}}%
 \textoC{1.7}{\huge \textbf{\@titulo\relax} \normalsize}%
 \ifthenelse{\equal{\@subtitulo}{}}{}{%
  \textoC{1.2}{\Large \textbf{\@subtitulo} \normalsize \relax} }%
 \vspace*{\stretch{1.5}}%
 \par%
 \margemD{%
  \ifthenelse{\boolean{tese}}%
   {Tese apresentada ao Programa de P\'os--Gradua\c c\~ao %
    do \@unidade\ da \@universidade, como requisito parcial %
    para obten\c c\~ao do t\'itulo de Doutor em \@programa.}{%
  \ifthenelse{\boolean{diss}}%
   {Disserta\c{c}\~{a}o apresentada ao Programa de P\'os--Gradua\c c\~ao\ %
    do \@unidade\ da \@universidade, como requisito parcial para %
    obten\c c\~ao do t\'itulo de Mestre em \@programa.}{%
  \ifthenelse{\boolean{mngr}}%
   {Monografia apresentada ao Programa de P\'os--Gradua\c c\~ao %
    do \@unidade\ da \@universidade, como requisito parcial para\ %
    obten\c c\~ao do Certificado de Especializa\c{c}\~ao em \@programa.}%
   {Trabalho de Conclus\~ao apresentado \`a Coordena\c c\~ao do Curso de \@programa\ do\ %
    \@unidade\ da\ \@universidade, como requisito parcial para obten\c c\~ao do\ %
    t\'itulo de Bacharel em \@programa.}}}}%
 \vspace*{\stretch{.2}}%
 \par%
 \margemD{\textbf{\'Area de concentra\c c\~ao:} \@concentracao.}%
 \vspace*{\stretch{.2}}%
 \par%
 \ifthenelse{\equal{\@orientador}{}}
  {\margemD{\textbf{Orientadora:} Profa. \@orientadora}}%
  {\margemD{\textbf{Orientador:} Prof. \@orientador}}%
 \ifthenelse{\equal{\@coorientador}{}}
  {\ifthenelse{\equal{\@coorientadora}{}}
   {}
   {\vspace*{\stretch{.2}}%
    \par%
    \margemD{\textbf{Co--Orientadora:} Profa. \@coorientadora}}%
  }
  {\vspace*{\stretch{.2}}%
   \par%
   \margemD{\textbf{Co--Orientador:} Prof. \@coorientador}}%
 \vspace*{\stretch{6}}%
 \par%
 \textoC{1}{\@cidade \\ \@ano}%
 \onehalfspacing%
 \normalfont%
 \clearpage%
}

%% Termo de aprovação
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\newcommand{\banca}[2]{\textoC{1}{\rule{.7\textwidth}{0.5pt}\\ \small \textbf{Prof. #1}\\#2} \vspace*{\stretch{0.5}}\par}
\newcommand{\profa}[2]{\textoC{1}{\rule{.7\textwidth}{0.5pt}\\ \small \textbf{Profa. #1}\\#2} \vspace*{\stretch{0.5}}\par}

\newenvironment{aprovacao}{
 \ifpdf
  \pdfbookmark[1]{Aprovação}{pretexto.3}
 \fi
 \singlespacing
 \par
 \textoC{1}{\Large \scshape \@autor \normalsize \upshape}
 \vspace*{\stretch{2}}
 \par
 \textoC{1.7}{\huge \textbf{\@titulo\relax} \normalsize}
 \ifthenelse{\equal{\@subtitulo}{}}{}{
  \textoC{1.2}{\Large \textbf{\@subtitulo\relax} \normalsize}}
 \vspace*{\stretch{1.0}}
 \par
 \textoF{
  \ifthenelse{\boolean{tese}}%
   {Tese defendida no Programa de P\'os--Gradua\c c\~ao %
    do \@unidade\ da \@universidade\ como requisito parcial %
    para obten\c c\~ao do t\'itulo de Doutor em \@programa, aprovada em %
    \@dia\ de\@mesP\ de \@ano, pela Banca Examinadora constitu\'{i}da pelos professores:}{%
  \ifthenelse{\boolean{diss}}%
   {Disserta\c{c}\~{a}o defendida no Programa de P\'os--Gradua\c c\~ao %
    do \@unidade\ da \@universidade\ como requisito parcial %
    para obten\c c\~ao do t\'itulo de Mestre em \@programa, aprovada em %
    \@dia\ de\@mesP\ de \@ano, pela Banca Examinadora constitu\'{i}da pelos professores:}{%
  \ifthenelse{\boolean{mngr}}%
   {Monografia apresentada no Programa de P\'os--Gradua\c c\~ao %
    do \@unidade\ da \@universidade\ como requisito parcial %
    para obten\c c\~ao do Certificado de Especializa\c{c}\~ao em \@programa, aprovada em %
    \@dia\ de\@mesP\ de \@ano, pela Banca Examinadora constitu\'{i}da pelos professores:}%
   {Trabalho de Conclus\~ao apresentado \`a Coordena\c c\~ao do Curso de \@programa\ do\ %
    \@unidade\ da\ \@universidade\ como requisito parcial para obten\c c\~ao do\ %
    t\'itulo de Bacharel em \@programa, aprovada em \@dia\ de\@mesP\ de \@ano, %
    pela Banca Examinadora constitu\'{i}da pelos professores:}%
    }}}
 \vspace*{\stretch{1.5}}
 \par
 \ifthenelse{\equal{\@orientador}{}}
  {\profa{\@orientadora}{\@unidade\ -- \@uni\\Presidente da Banca}}
  {\banca{\@orientador}{\@unidade\ -- \@uni\\Presidente da Banca}}
 \ifthenelse{\equal{\@coorientador}{}}
  {\ifthenelse{\equal{\@coorientadora}{}}
   {}
   {\profa{\@coorientadora}{\@unidadeco\ -- \@unico}}
  }
  {\banca{\@coorientador}{\@unidadeco\ -- \@unico}}
}
{%
 \clearpage%
}

%% Direitos autorais
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\newcommand{\direitos}[1]{
 \ifpdf
  \pdfbookmark[1]{Direitos Autorais}{pretexto.4}
 \fi
 \singlespacing\arial%
 \margem{\normalfont \normalsize Todos os direitos reservados. \'{E} proibida
  a reprodu\c{c}\~{a}o total ou parcial do trabalho sem autoriza\c{c}\~{a}o da
  universidade, do autor e do orientador(a).}%
 \vspace*{\stretch{2}}%
 \par%
 \margem{\arial \textbf{\@autor}}%
 \vspace*{\stretch{0.2}}%
 \par%
 \margem{\normalfont #1}%
 \clearpage\onehalfspacing\normalfont%
}

%% dedicatoria
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\newenvironment{dedicatoria}{
 \ifpdf
  \pdfbookmark[1]{Dedicatória}{pretexto.5} % Sets a PDF bookmark for the abstract
 \fi
 \normalfont\vspace*{\stretch{1}}
}{\clearpage}

%% Agradecimentos
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\newenvironment{agradecimentos}{
 \ifpdf
  \pdfbookmark[1]{Agradecimentos}{pretexto.6}
 \fi
 \@makeschapterhead{Agradecimentos}
}{\clearpage}

%% Resumo
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\newenvironment{resumo}{%
 \ifpdf
  \pdfbookmark[1]{Resumo}{pretexto.7}
 \fi
 
 \@makeschapterhead{Resumo}
 \begin{minipage}{13.5cm}
  \singlespacing%
  \@autorR.
  \textbf{\@titulo}.
  \@cidade, \@ano.
  \pageref{endpage}p.
  \ifthenelse{\boolean{tese}}{Tese de Doutorado}
 {\ifthenelse{\boolean{diss}}{Disserta\c{c}\~{a}o de Mestrado}}
 {\ifthenelse{\boolean{mngr}}{Monografia de Especializa\c{c}\~{a}o}
                             {Relat\'{o}rio de Gradua\c{c}\~{a}o}}.
  \ifthenelse{\equal{\@departamento}{}}{}{\@departamento,}
  \ifthenelse{\equal{\@unidade}{}}{}{\@unidade,} \@universidade.%
 \end{minipage}
 \onehalfspacing%
 \vspace*{\stretch{1}}%
 \par%
 \noindent\begin{minipage}{15cm}%
}
{%
 \end{minipage}%
 \vspace*{\stretch{3}}%
 \par%
 \noindent \arial \textbf{Palavras--chave} \normalfont \normalsize%
 \par%
 \indent \@chaves%
 \vspace*{\stretch{4}}%
 \par%
 \clearpage%
}

%% Abstract
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\renewenvironment{abstract}[1]{%
 \ifpdf
  \pdfbookmark[1]{Abstract}{pretexto.8} % Sets a PDF bookmark for the abstract
 \fi
  \@makeschapterhead{Abstract}
  \begin{minipage}{13.5cm}
   \singlespacing%
   \@autorR.
   \textbf{#1}.
   \@cidade, \@ano.
   \pageref{endpage}p.
  \ifthenelse{\boolean{tese}}{PhD. Thesis}
 {\ifthenelse{\boolean{diss}}{MSc. Dissertation}}
 {\ifthenelse{\boolean{mngr}}{Monografia de Especializa\c{c}\~{a}o}
                             {Relat\'{o}rio de Gradua\c{c}\~{a}o}}.
  \ifthenelse{\equal{\@departamento}{}}{}{\@departamento,}
  \ifthenelse{\equal{\@unidade}{}}{}{\@unidade,} \@universidade.%

  \end{minipage}\onehalfspacing%
  \vspace*{\stretch{1}}%
  \par%
  \noindent\begin{minipage}{15cm}%
  }
  {%
  \end{minipage}%
  \vspace*{\stretch{3}}%
  \par%
  \noindent \arial \textbf{Keywords} \normalfont \normalsize%
  \par%
  \indent \@keys%
  \vspace*{\stretch{4}}%
  \par%
  \clearpage%
  }

%% Epígrafe
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
\newcommand{\epigrafe}[2]{%
  \ifpdf
   \pdfbookmark[1]{Epígrafe}{pretexto.9}
  \fi
  \thispagestyle{empty}\singlespacing\normalfont%
  \vspace*{\stretch{1}}\par%
  \begin{quotation}%
  #1%
  \par%
  \begin{flushright}
  \textbf{#2}.
  \end{flushright}%
  \end{quotation}%
  \onehalfspacing
  \clearpage%
}

%% Sumário
%% - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
%% The \IfSubStringInString command is based on H. Harders "substr" class.
%%
%% expands the first and second argument with
%% \protected@edef and calls #3 with them:
\newcommand\su@ExpandTwoArgs[3]{%
  \protected@edef\su@SubString{#1}%
  \protected@edef\su@String{#2}%
  \expandafter\expandafter\expandafter#3%
  \expandafter\expandafter\expandafter{%
    \expandafter\su@SubString\expandafter
  }\expandafter{\su@String}%
}
%%
%% tests if #1 in #2. If yes execute #3, else #4
\newcommand*\IfSubStringInString[2]{%
  \su@ExpandTwoArgs{#1}{#2}\su@IfSubStringInString
}
%%
\newcommand*\su@IfSubStringInString[2]{%
  \def\su@compare##1#1##2\@nil{%
    \def\su@param{##2}%
    \ifx\su@param\@empty
      \expandafter\@secondoftwo
    \else
      \expandafter\@firstoftwo
    \fi
  }%
  \su@compare#2#1\@nil
}
%%
\newcommand{\tabelas}[1][opt]
{
\ifpdf
 \pdfbookmark[0]{Sumário}{sumario}
\fi
\clearpage\singlespacing%
\tableofcontents%
\clearpage%
\IfSubStringInString{fig}{#1}
 {\listoffigures\clearpage
 }{}
\IfSubStringInString{tab}{#1}
 {\listoftables\clearpage
 }{}
\IfSubStringInString{alg}{#1}
 {\listofalgorithmes
  \addcontentsline{toc}{chapter}{Lista de Algoritmos}\clearpage
 }{}
\IfSubStringInString{cod}{#1}
 {%\listofcodes
  \lstlistoflistings
  \addcontentsline{toc}{chapter}{Lista de C\'{o}digos de Programas}\clearpage
 }{}

\normalfont\pagestyle{fancy}%
\onehalfspacing
\pagenumbering{arabic}
\setcounter{page}{1}
}

\makeatother


%%======================================================================
%% inf-ufg Class Delayed Codes
%%======================================================================
\AtBeginDocument{%
  \author{\LARGE \arial \autor}%
  \title{\Huge \arial \titulo}%
  \date{\large \arial \data}%
  \ifthenelse{\boolean{abnt}}
    {\bibliographystyle{abnt-alf}}%
    {\bibliographystyle{inf-ufg}}%
  \pagestyle{empty}%
  }
\AtEndDocument{%
  \label{endpage}%
  }

%% Local Variables:
%% mode: LaTeX
%% End:
\endinput
%%======================================================================
%% End of file inf-ufg.cls'.
%%======================================================================
