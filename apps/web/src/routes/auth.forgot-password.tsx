import { createFileRoute, Link } from '@tanstack/react-router'
import { CheckCircle2, Loader2 } from 'lucide-react'
import { useState } from 'react'
import { api } from '#/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

export const Route = createFileRoute('/auth/forgot-password')({ component: ForgotPasswordPage })

interface ForgotPasswordResponse {
  message: string
}

function ForgotPasswordPage() {
  const [isLoading, setIsLoading] = useState(false)
  const [submitted, setSubmitted] = useState(false)
  const [error, setError] = useState('')
  const [fieldErrors, setFieldErrors] = useState<{ email?: string }>({})

  async function handleSubmit(e: React.SyntheticEvent<HTMLFormElement>) {
    e.preventDefault()
    const fd = new FormData(e.currentTarget)
    const email = (fd.get('email') as string).trim()
    if (!email || !/\S+@\S+\.\S+/.test(email)) {
      setFieldErrors({ email: 'Enter a valid email' })
      return
    }
    setFieldErrors({})
    setError('')
    setIsLoading(true)
    try {
      await api.post<ForgotPasswordResponse>('/api/auth/forgot-password', { email })
      // Show the same confirmation regardless of whether the email
      // matched a real account — the backend deliberately returns the
      // same response to prevent account enumeration.
      setSubmitted(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong')
    } finally {
      setIsLoading(false)
    }
  }

  if (submitted) {
    return (
      <div className="space-y-7">
        <div className="space-y-1">
          <h1 className="text-2xl font-bold tracking-tight">Check your email</h1>
          <p className="text-sm text-muted-foreground">
            If an account exists for that address, we&apos;ve sent a link you can use to reset your password.
          </p>
        </div>
        <div
          className="border px-4 py-3 text-sm flex items-start gap-3"
          style={{
            borderColor: 'color-mix(in oklab, var(--success-500) 30%, transparent)',
            background: 'color-mix(in oklab, var(--success-500) 10%, transparent)',
          }}
        >
          <CheckCircle2
            className="h-4 w-4 mt-0.5 shrink-0"
            style={{ color: 'var(--success-500)' }}
            aria-hidden
          />
          <span>
            The link is single-use and expires shortly. Didn&apos;t get it? Check your spam folder, or try again in a
            few minutes.
          </span>
        </div>
        <p className="text-center text-sm text-muted-foreground">
          <Link
            to="/auth/login"
            search={{ redirect: undefined }}
            className="font-medium text-foreground underline-offset-4 hover:underline"
          >
            Back to sign in
          </Link>
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-7">
      <div className="space-y-1">
        <h1 className="text-2xl font-bold tracking-tight">Reset your password</h1>
        <p className="text-sm text-muted-foreground">
          Enter the email on your account and we&apos;ll send you a link to choose a new password.
        </p>
      </div>

      {error && (
        <div className="border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4" noValidate>
        <div className="space-y-1.5">
          <label htmlFor="forgot-email" className="text-sm font-medium">
            Email
          </label>
          <Input
            id="forgot-email"
            name="email"
            type="email"
            placeholder="you@example.com"
            autoComplete="email"
            autoFocus
            onChange={() => setFieldErrors({})}
          />
          {fieldErrors.email && <p className="text-xs text-destructive">{fieldErrors.email}</p>}
        </div>

        <Button type="submit" className="w-full" disabled={isLoading}>
          {isLoading ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Sending link…
            </>
          ) : (
            'Send reset link'
          )}
        </Button>
      </form>

      <p className="text-center text-sm text-muted-foreground">
        Remembered it?{' '}
        <Link
          to="/auth/login"
          search={{ redirect: undefined }}
          className="font-medium text-foreground underline-offset-4 hover:underline"
        >
          Sign in
        </Link>
      </p>
    </div>
  )
}
