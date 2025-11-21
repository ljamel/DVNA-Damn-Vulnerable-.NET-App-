using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace SecurityAnalyzer
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class SecurityAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor WeakCryptoRule =
            new DiagnosticDescriptor(
                id: "SEC001",
                title: "Cryptographie faible",
                messageFormat: "L'utilisation de '{0}' est considérée comme non sécurisée.",
                category: "Security",
                DiagnosticSeverity.Warning,
                isEnabledByDefault: true);

        private static readonly DiagnosticDescriptor DangerousApiRule =
            new DiagnosticDescriptor(
                id: "SEC002",
                title: "Usage dangereux d'API",
                messageFormat: "L'appel à '{0}' peut être dangereux.",
                category: "Security",
                DiagnosticSeverity.Warning,
                isEnabledByDefault: true);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
            ImmutableArray.Create(WeakCryptoRule, DangerousApiRule);

        public override void Initialize(AnalysisContext context)
        {
            context.EnableConcurrentExecution();
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            context.RegisterSyntaxNodeAction(AnalyzeInvocation, Microsoft.CodeAnalysis.CSharp.SyntaxKind.InvocationExpression);
            context.RegisterSyntaxNodeAction(AnalyzeObjectCreation, Microsoft.CodeAnalysis.CSharp.SyntaxKind.ObjectCreationExpression);
        }

        private void AnalyzeObjectCreation(SyntaxNodeAnalysisContext ctx)
        {
            var symbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol as IMethodSymbol;
            if (symbol == null) return;

            // Cryptographie faible
            if (symbol.ContainingType.ToString() == "System.Security.Cryptography.MD5")
            {
                ctx.ReportDiagnostic(Diagnostic.Create(WeakCryptoRule, ctx.Node.GetLocation(), symbol.ContainingType.Name));
            }

            if (symbol.ContainingType.ToString() == "System.Security.Cryptography.SHA1")
            {
                ctx.ReportDiagnostic(Diagnostic.Create(WeakCryptoRule, ctx.Node.GetLocation(), symbol.ContainingType.Name));
            }

        }

        private void AnalyzeInvocation(SyntaxNodeAnalysisContext ctx)
        {
            var symbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol as IMethodSymbol;
            if (symbol == null) return;

            // Process.Start(path) → dangereux detecte injection de commande
            if (symbol.ContainingType.ToString() == "System.Diagnostics.Process" &&
                symbol.Name == "Start" &&
                symbol.Parameters.Length == 1)
            {
                ctx.ReportDiagnostic(Diagnostic.Create(DangerousApiRule, ctx.Node.GetLocation(), "Process.Start(string)"));
            }
        }
    }
}
