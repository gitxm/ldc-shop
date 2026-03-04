"use client"

import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { useI18n } from "@/lib/i18n/context"

export function SignInButton() {
    const { t } = useI18n()
    const router = useRouter()

    return (
        <Button
            size="sm"
            className="bg-foreground text-background hover:bg-foreground/90"
            onClick={() => router.push("/login")}
        >
            {t('common.login')}
        </Button>
    )
}
